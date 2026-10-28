"""Versioned synthetic Isolation Forest, deterministic baseline, disjoint holdout."""

import hashlib
import time

import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_VERSION = "iforest-synthetic-v2-seed2401"


def synthetic(seed: int, count: int = 512, anomaly: bool = False):
    rng = np.random.default_rng(seed)
    if anomaly:
        values = rng.normal([102, 13, 2400], [7, 2, 150], (count, 3))
    else:
        values = rng.normal([63, 2, 1500], [3, 0.35, 65], (count, 3))
    values[:, 2] = np.round(values[:, 2])
    return values


def rule_baseline(values):
    x = np.asarray(values)
    return (x[:, 0] > 85) | (x[:, 1] > 7) | (x[:, 2] > 2100) | (x[:, 2] < 900)


class AnomalyModel:
    def __init__(self, training=None, version: str = MODEL_VERSION):
        self.training = synthetic(2401) if training is None else np.asarray(training, dtype=float)
        self.version = version
        self.model = IsolationForest(
            n_estimators=128, contamination=0.02, random_state=2401, n_jobs=1
        ).fit(self.training)

    def classify(self, reading: dict) -> str | None:
        values = [[reading["temp_c"], reading["vibration_mm_s"], reading["rpm"]]]
        if self.model.predict(values)[0] != -1:
            return None
        return "HIGH" if rule_baseline(values)[0] else "LOW"


def evaluate_model() -> dict:
    start = time.perf_counter()
    model = AnomalyModel()
    fitted = hashlib.sha256()
    fitted.update(model.training.tobytes())
    fitted.update(np.asarray([model.model.offset_], dtype="<f8").tobytes())
    for estimator in model.model.estimators_:
        tree = estimator.tree_
        for array in (
            tree.children_left,
            tree.children_right,
            tree.feature,
            tree.threshold,
            tree.n_node_samples,
        ):
            fitted.update(array.astype(array.dtype.newbyteorder("<")).tobytes())
    test = np.concatenate([synthetic(2402, 256), synthetic(2403, 128, True)])
    labels = np.concatenate([np.zeros(256, dtype=bool), np.ones(128, dtype=bool)])
    results = {}
    for name, predicted in {
        "isolation_forest": model.model.predict(test) == -1,
        "rule_baseline": rule_baseline(test),
    }.items():
        tp = int(np.sum(predicted & labels))
        fp = int(np.sum(predicted & ~labels))
        tn = int(np.sum(~predicted & ~labels))
        fn = int(np.sum(~predicted & labels))
        results[name] = {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else 0,
            "recall": tp / (tp + fn) if tp + fn else 0,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0,
            "false_positive_rate": fp / (fp + tn),
            "false_negative_rate": fn / (tp + fn),
        }
    return {
        "model_version": MODEL_VERSION,
        "dataset_version": "synthetic-v2",
        "training_seed": 2401,
        "holdout_seeds": [2402, 2403],
        "training_count": 512,
        "holdout_count": 384,
        "normal_count": 256,
        "anomaly_count": 128,
        "training_sha256": hashlib.sha256(model.training.tobytes()).hexdigest(),
        "fitted_model_sha256": fitted.hexdigest(),
        "estimator_config": {
            "n_estimators": 128,
            "contamination": 0.02,
            "random_state": 2401,
            "n_jobs": 1,
            "max_samples": "auto",
        },
        "offset": float(model.model.offset_),
        "results": results,
        "duration_seconds": time.perf_counter() - start,
        "limitation": "Synthetic separable distributions; not field accuracy.",
    }
