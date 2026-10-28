"""Reviewed learning, promotion gates, encrypted recipes and rollback."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import numpy as np
import pytest
import sklearn
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from privacygate_v2.learning import LearningError, ModelStore, reviewed_candidate
from privacygate_v2.model import MODEL_VERSION, AnomalyModel, synthetic
from privacygate_v2.repository import Repository
from privacygate_v2.security import b64, canonical


@pytest.fixture
def learning(tmp_path):
    repo = Repository(tmp_path / "gateway.db")
    key = os.urandom(32)
    cipher = AESGCM(key)
    (tmp_path / "config.json").write_text(
        json.dumps({"runtime_root": str(tmp_path), "raw_key_b64": b64(key)}), encoding="utf-8"
    )
    store = ModelStore(tmp_path, cipher)
    owner = {"account_id": str(uuid4()), "role": "owner"}
    resource = "0x" + "a" * 64
    device = str(uuid4())
    repo.execute(
        "INSERT INTO accounts VALUES(?,?,?,?)", (owner["account_id"], "owner", "owner", "hash")
    )
    repo.execute(
        "INSERT INTO devices VALUES(?,?,?,?,?,0,1)",
        (resource, owner["account_id"], device, "Synthetic equipment", "public-key"),
    )

    def samples(training, normal, anomaly):
        rows = np.concatenate([training, normal, anomaly])
        now = int(time.time())
        with repo.connection() as db:
            for seq, values in enumerate(rows, 1):
                raw = dict(zip(("temp_c", "vibration_mm_s", "rpm"), values.tolist()))
                aad = canonical({"resource_id": resource, "device_id": device, "sequence": seq})
                nonce = os.urandom(12)
                db.execute(
                    "INSERT INTO telemetry(resource_id,device_id,sequence,accepted_at,nonce,ciphertext) VALUES(?,?,?,?,?,?)",
                    (resource, device, seq, now, nonce, cipher.encrypt(nonce, canonical(raw), aad)),
                )
        return {
            "schema_version": 1,
            "resource_id": resource,
            "training_sequences": list(range(1, len(training) + 1)),
            "validation": [
                {
                    "sequence": i + len(training) + 1,
                    "label": "normal" if i < len(normal) else "anomaly",
                }
                for i in range(len(normal) + len(anomaly))
            ],
        }

    return repo, cipher, store, owner, resource, samples


def shifted(seed, count):
    rows = synthetic(seed, count)
    rows[:, 0] += 8
    return rows


def candidate(learning):
    repo, cipher, store, owner, _, samples = learning
    review = samples(shifted(5001, 256), shifted(5002, 64), synthetic(5003, 64, True))
    report, bundle = reviewed_candidate(repo, cipher, store, owner, review)
    return report, bundle, review


def test_retraining_improves_shifted_normal_patterns_and_survives_restart(learning):
    _, cipher, store, _, resource, _ = learning
    report, bundle, _ = candidate(learning)
    assert report["eligible"], report
    assert report["candidate"]["f1"] > report["incumbent"]["f1"]
    assert report["candidate"]["recall"] >= report["incumbent"]["recall"]
    store.promote(resource, bundle, report["incumbent_version"])
    restarted = ModelStore(store.root.parent, cipher).select(resource, AnomalyModel())
    expected = AnomalyModel(bundle["training"], bundle["version"])
    np.testing.assert_array_equal(
        restarted.model.predict(shifted(5004, 30)), expected.model.predict(shifted(5004, 30))
    )
    assert restarted.version == bundle["version"]
    blob = store.path(resource).read_bytes()
    assert b"training" not in blob and b"temp_c" not in blob
    assert '"training":' not in json.dumps(report)
    assert store.rollback(resource)["model_version"] == MODEL_VERSION
    assert (
        ModelStore(store.root.parent, cipher).select(resource, AnomalyModel()).version
        == MODEL_VERSION
    )


def test_unhelpful_candidate_is_ineligible(learning):
    repo, cipher, store, owner, _, samples = learning
    review = samples(
        synthetic(5011, 32),
        np.tile([63.0, 2.0, 1500], (40, 1)),
        np.tile([104.0, 13.0, 2400], (40, 1)),
    )
    report, _ = reviewed_candidate(repo, cipher, store, owner, review)
    assert report["incumbent"]["f1"] == 1
    assert not report["eligible"]
    assert not report["activated"]
    assert not store.path(review["resource_id"]).exists()


@pytest.mark.parametrize(
    "failure",
    ["reader", "other-owner", "overlap", "missing", "expired", "one-class", "duplicate-features"],
)
def test_bad_reviews_never_create_artifacts(learning, failure):
    repo, cipher, store, owner, resource, samples = learning
    training = shifted(5001, 64)
    normal = shifted(5002, 20)
    if failure == "duplicate-features":
        normal[0] = training[0]
    review = samples(training, normal, synthetic(5003, 20, True))
    if failure == "reader":
        owner = {**owner, "role": "reader"}
    if failure == "other-owner":
        owner = {**owner, "account_id": str(uuid4())}
    if failure == "overlap":
        review["validation"][0]["sequence"] = review["training_sequences"][0]
    if failure == "missing":
        review["training_sequences"][0] = 99999
    if failure == "expired":
        repo.execute("UPDATE telemetry SET accepted_at=?", (int(time.time()) - 8 * 86400,))
    if failure == "one-class":
        for row in review["validation"]:
            row["label"] = "normal"
    with pytest.raises(LearningError):
        reviewed_candidate(repo, cipher, store, owner, review)
    assert not store.path(resource).exists()


def test_artifact_tampering_wrong_resource_and_expiry(learning, monkeypatch):
    _, _cipher, store, _, resource, _ = learning
    report, bundle, _ = candidate(learning)
    store.promote(resource, bundle, report["incumbent_version"])
    other = "0x" + "b" * 64
    store.path(other).write_bytes(store.path(resource).read_bytes())
    with pytest.raises(LearningError, match="INVALID_MODEL_ARTIFACT"):
        store.select(other, AnomalyModel())
    store.path(other).unlink()
    original = store.path(resource).read_bytes()
    damaged = bytearray(original)
    damaged[-1] ^= 1
    store.path(resource).write_bytes(damaged)
    with pytest.raises(LearningError, match="INVALID_MODEL_ARTIFACT"):
        store.select(resource, AnomalyModel())
    store.path(resource).write_bytes(original)
    loaded = store.select(resource, AnomalyModel())
    assert loaded.version == bundle["version"]
    monkeypatch.setattr(time, "time", lambda: bundle["expires_at"] + 1)
    assert store.select(resource, AnomalyModel()).version == MODEL_VERSION
    assert store.read(resource) == {"current": None, "previous": None}


def test_concurrent_updates_and_previous_recipe_retention(learning, monkeypatch):
    _, cipher, store, _, resource, _ = learning
    report, bundle, _ = candidate(learning)
    with store.writer(resource), pytest.raises(LearningError, match="MODEL_UPDATE_BUSY"):
        store.promote(resource, bundle, report["incumbent_version"])
    earlier = {**bundle, "expires_at": bundle["expires_at"] - 60}
    store.write(resource, {"current": bundle, "previous": earlier})
    restarted = ModelStore(store.root.parent, cipher)
    assert restarted.select(resource, AnomalyModel()).version == bundle["version"]
    monkeypatch.setattr(time, "time", lambda: earlier["expires_at"] + 1)
    assert restarted.select(resource, AnomalyModel()).version == bundle["version"]
    assert restarted.read(resource)["previous"] is None


def test_stale_promotion_and_dependency_mismatch(learning):
    _, _, store, _, resource, _ = learning
    report, bundle, _ = candidate(learning)
    store.promote(resource, bundle, report["incumbent_version"])
    with pytest.raises(LearningError, match="MODEL_CHANGED_OR_EXPIRED"):
        store.promote(resource, bundle, MODEL_VERSION)
    bad = {**bundle, "sklearn_version": "wrong-version"}
    assert sklearn.__version__ != "wrong-version"
    store.write(resource, {"current": bad, "previous": None})
    with pytest.raises(LearningError, match="INVALID_MODEL_ARTIFACT"):
        store.select(resource, AnomalyModel())


def test_cli_evaluate_activate_restart_and_rollback(learning):
    _, _, store, _, resource, samples = learning
    review = samples(shifted(5001, 256), shifted(5002, 64), synthetic(5003, 64, True))
    root = store.root.parent
    manifest = root / "review.json"
    manifest.write_text(json.dumps(review), encoding="utf-8")
    script = Path(__file__).resolve().parents[4] / "infra/scripts/v2/retrain.py"
    command = [
        sys.executable,
        str(script),
        "--config",
        str(root / "config.json"),
        "--owner",
        "owner",
        "--resource",
        resource,
    ]
    result = subprocess.run(
        command + ["--review", str(manifest)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["eligible"]
    assert not store.path(resource).exists()
    result = subprocess.run(
        command + ["--review", str(manifest), "--activate"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["activated"]
    # Same candidate cannot beat itself and must not replace the active artifact.
    previous = store.path(resource).read_bytes()
    result = subprocess.run(
        command + ["--review", str(manifest), "--activate"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 2, result.stderr
    assert store.path(resource).read_bytes() == previous
    result = subprocess.run(
        command + ["--rollback"], capture_output=True, text=True, check=False, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["model_version"] == MODEL_VERSION
