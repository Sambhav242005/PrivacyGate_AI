"""Local, reviewed batch learning. No public routes, automatic labels or pickle."""

import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import numpy as np
import sklearn
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import Field

from .model import MODEL_VERSION, AnomalyModel, rule_baseline, synthetic
from .schemas import StrictBody, resource_string
from .security import canonical, digest

FEATURES = ("temp_c", "vibration_mm_s", "rpm")
RETENTION = 7 * 86400
MAX_ROWS = 4096


class LearningError(ValueError):
    """Safe error code. Never include raw features or keys in a report/error."""


class ReviewLabel(StrictBody):
    sequence: int = Field(gt=0)
    label: str = Field(pattern="^(normal|anomaly)$")


class Review(StrictBody):
    schema_version: int = Field(ge=1, le=1)
    resource_id: str
    training_sequences: list[int] = Field(min_length=32, max_length=MAX_ROWS)
    validation: list[ReviewLabel] = Field(min_length=40, max_length=MAX_ROWS)


def metrics(model, values, labels) -> dict:
    predicted = model.predict(values) == -1
    labels = np.asarray(labels, dtype=bool)
    tp = int(np.sum(predicted & labels))
    fp = int(np.sum(predicted & ~labels))
    tn = int(np.sum(~predicted & ~labels))
    fn = int(np.sum(~predicted & labels))
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }


def non_regressing(candidate: dict, incumbent: dict) -> bool:
    return all(candidate[k] >= incumbent[k] for k in ("precision", "recall", "f1")) and (
        candidate["false_positive_rate"] <= incumbent["false_positive_rate"]
    )


def features(values):
    rows = np.asarray(values, dtype=float)
    if (
        rows.ndim != 2
        or rows.shape[1] != 3
        or not 32 <= len(rows) <= MAX_ROWS + 512
        or not np.isfinite(rows).all()
        or not ((rows[:, 0] >= -50) & (rows[:, 0] <= 200)).all()
        or not ((rows[:, 1] >= 0) & (rows[:, 1] <= 100)).all()
        or not ((rows[:, 2] >= 0) & (rows[:, 2] <= 20000)).all()
        or not (rows[:, 2] == np.round(rows[:, 2])).all()
    ):
        raise LearningError("INVALID_TRAINING_DATA")
    return rows


class ModelStore:
    """Encrypted JSON training recipes, refitted with pinned dependencies at startup.

    Reuses the gateway's AES-GCM raw-data key and protected runtime directory.
    No executable estimator deserialization. Active and previous recipes expire
    no later than the oldest source reading's existing seven-day retention.
    """

    def __init__(self, root: Path, cipher: AESGCM):
        self.root = root / "models"
        self.cipher = cipher
        self.cache: dict[str, tuple[AnomalyModel, int]] = {}

    def path(self, resource_id: str) -> Path:
        resource_string(resource_id)
        return self.root / f"{resource_id}.enc"

    @staticmethod
    def aad(resource_id: str) -> bytes:
        return canonical({"purpose": "reviewed-model-v1", "resource_id": resource_id})

    @contextmanager
    def writer(self, resource_id: str):
        self.root.mkdir(parents=True, exist_ok=True)
        lock = self.path(resource_id).with_suffix(".lock")
        try:
            handle = lock.open("xb")
        except FileExistsError:
            raise LearningError("MODEL_UPDATE_BUSY") from None
        try:
            handle.close()
            yield
        finally:
            lock.unlink()

    def read(self, resource_id: str) -> dict:
        target = self.path(resource_id)
        if not target.exists():
            return {"current": None, "previous": None}
        try:
            if target.stat().st_size > 2_000_000:
                raise ValueError
            blob = target.read_bytes()
            data = json.loads(self.cipher.decrypt(blob[:12], blob[12:], self.aad(resource_id)))
            if set(data) != {"current", "previous"}:
                raise ValueError
            for bundle in data.values():
                if bundle is not None:
                    if (
                        set(bundle) != {"version", "training", "expires_at", "sklearn_version"}
                        or bundle["sklearn_version"] != sklearn.__version__
                        or type(bundle["expires_at"]) is not int
                        or bundle["version"] != self.version(bundle["training"])
                    ):
                        raise ValueError
                    features(bundle["training"])
            return data
        except (
            ValueError,
            TypeError,
            KeyError,
            OSError,
            InvalidTag,
            OverflowError,
            AttributeError,
        ):
            raise LearningError("INVALID_MODEL_ARTIFACT") from None

    def write(self, resource_id: str, data: dict):
        self.root.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(12)
        blob = nonce + self.cipher.encrypt(nonce, canonical(data), self.aad(resource_id))
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.root, suffix=".tmp", delete=False) as out:
                temp_path = Path(out.name)
                out.write(blob)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp_path, self.path(resource_id))
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def current(self, resource_id: str) -> dict | None:
        data = self.read(resource_id)
        expired = [k for k, v in data.items() if v and v["expires_at"] <= time.time()]
        if expired:
            # Prune both slots under the same writer lock used for activation.
            with self.writer(resource_id):
                data = self.read(resource_id)
                for k, v in data.items():
                    if v and v["expires_at"] <= time.time():
                        data[k] = None
                self.write(resource_id, data)
        return data["current"]

    def select(self, resource_id: str, default: AnomalyModel) -> AnomalyModel:
        if resource_id in self.cache:
            model, expiry = self.cache[resource_id]
            if expiry > time.time():
                return model
            del self.cache[resource_id]
        bundle = self.current(resource_id)
        if bundle:
            model = AnomalyModel(bundle["training"], bundle["version"])
            deadlines = [v["expires_at"] for v in self.read(resource_id).values() if v]
            self.cache[resource_id] = model, min(deadlines)
            return model
        self.cache[resource_id] = default, 2**63 - 1
        return default

    @staticmethod
    def version(training) -> str:
        return "iforest-reviewed-v1-" + digest(canonical(training))[:16]

    def promote(self, resource_id: str, bundle: dict, expected_version: str):
        with self.writer(resource_id):
            data = self.read(resource_id)
            current = data["current"]
            actual = (
                current["version"]
                if current and current["expires_at"] > time.time()
                else MODEL_VERSION
            )
            if actual != expected_version or bundle["expires_at"] <= time.time():
                raise LearningError("MODEL_CHANGED_OR_EXPIRED")
            self.write(resource_id, {"current": bundle, "previous": current})

    def rollback(self, resource_id: str) -> dict:
        with self.writer(resource_id):
            data = self.read(resource_id)
            previous = data["previous"]
            if previous and previous["expires_at"] <= time.time():
                raise LearningError("PREVIOUS_MODEL_EXPIRED")
            if not data["current"]:
                raise LearningError("NO_MODEL_TO_ROLL_BACK")
            self.write(resource_id, {"current": previous, "previous": None})
        return {
            "status": "rolled_back",
            "model_version": previous["version"] if previous else MODEL_VERSION,
        }


def reviewed_candidate(repo, cipher: AESGCM, store: ModelStore, owner: dict, review: dict):
    """Read only retained, owner-scoped encrypted records selected by sequence."""
    parsed = Review.model_validate(review)
    resource = resource_string(parsed.resource_id)
    device = repo.one("SELECT * FROM devices WHERE resource_id=?", (resource,))
    if owner["role"] != "owner" or not device or device["owner_id"] != owner["account_id"]:
        raise LearningError("OWNER_REQUIRED")
    train_ids = parsed.training_sequences
    valid_ids = [r.sequence for r in parsed.validation]
    all_ids = train_ids + valid_ids
    if (
        any(type(n) is not int or n < 1 for n in all_ids)
        or len(all_ids) > MAX_ROWS
        or len(set(all_ids)) != len(all_ids)
        or any(
            sum(r.label == label for r in parsed.validation) < 20 for label in ("normal", "anomaly")
        )
    ):
        raise LearningError("INVALID_REVIEW_SPLIT")
    values = []
    accepted = []
    for seq in all_ids:
        row = repo.one(
            "SELECT * FROM telemetry WHERE resource_id=? AND sequence=? AND accepted_at>?",
            (resource, seq, int(time.time()) - RETENTION),
        )
        if not row:
            raise LearningError("REVIEWED_READING_UNAVAILABLE")
        aad = canonical({"resource_id": resource, "device_id": row["device_id"], "sequence": seq})
        try:
            reading = json.loads(cipher.decrypt(row["nonce"], row["ciphertext"], aad))
            values.append([reading[k] for k in FEATURES])
        except (ValueError, TypeError, KeyError, InvalidTag):
            raise LearningError("INVALID_REVIEWED_READING") from None
        accepted.append(row["accepted_at"])
    values = features(values)
    train, validation = values[: len(train_ids)], values[len(train_ids) :]
    if len(np.unique(train, axis=0)) < 16:
        raise LearningError("INSUFFICIENT_TRAINING_DIVERSITY")
    current_bundle = store.current(resource)
    incumbent = (
        AnomalyModel()
        if current_bundle is None
        else AnomalyModel(current_bundle["training"], current_bundle["version"])
    )
    training = np.concatenate([synthetic(2401), train])
    # Reject exact feature leakage, including examples used by the incumbent.
    held = {tuple(row) for row in validation}
    if held.intersection(map(tuple, training)) or held.intersection(map(tuple, incumbent.training)):
        raise LearningError("TRAIN_VALIDATION_OVERLAP")
    # Preserve a fixed synthetic regression set, also disjoint from all training.
    regression = np.concatenate([synthetic(2402, 256), synthetic(2403, 128, True)])
    if set(map(tuple, regression)).intersection(map(tuple, training)):
        raise LearningError("REGRESSION_TRAINING_OVERLAP")
    version = store.version(training.tolist())
    candidate = AnomalyModel(training, version)
    labels = [r.label == "anomaly" for r in parsed.validation]
    before = metrics(incumbent.model, validation, labels)
    after = metrics(candidate.model, validation, labels)
    regression_labels = [False] * 256 + [True] * 128
    regression_before = metrics(incumbent.model, regression, regression_labels)
    regression_after = metrics(candidate.model, regression, regression_labels)
    eligible = (
        non_regressing(after, before)
        and after["f1"] > before["f1"]
        and non_regressing(regression_after, regression_before)
    )

    # Baseline comparison is informational: never claim ML superiority by default.
    class Rule:
        @staticmethod
        def predict(x):
            return np.where(rule_baseline(x), -1, 1)

    report = {
        "schema_version": 1,
        "resource_id": resource,
        "incumbent_version": incumbent.version,
        "candidate_version": version,
        "training_count": len(training),
        "validation_count": len(validation),
        "incumbent": before,
        "candidate": after,
        "rule_baseline": metrics(Rule(), validation, labels),
        "regression_incumbent": regression_before,
        "regression_candidate": regression_after,
        "eligible": eligible,
        "activated": False,
        "expires_at": min(accepted[: len(train_ids)]) + RETENTION,
        "limitation": "Reviewed validation informs promotion; use new independent data for final evaluation.",
    }
    bundle = {
        "version": version,
        "training": training.tolist(),
        "expires_at": report["expires_at"],
        "sklearn_version": sklearn.__version__,
    }
    return report, bundle
