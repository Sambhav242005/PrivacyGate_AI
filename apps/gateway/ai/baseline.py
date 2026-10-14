"""PG-015 deterministic rule baseline (stdlib only, no sklearn).

Thresholds chosen to sit between the synthetic normal/anomaly
distributions documented in dataset.py; calibrated for separation
on synthetic fixtures, NOT equipment failure prediction.
"""

from __future__ import annotations

MODEL_VERSION = "rule-v1"

TEMP_HIGH = 80.0
VIBRATION_HIGH = 5.0
RPM_LOW = 1200.0
RPM_HIGH = 1800.0


def predict(row: dict) -> tuple[bool, str, str]:
    """Return (is_anomaly, severity, event_type). Never raises on bad input."""
    try:
        temp = float(row.get("temp_c", 0.0))
        vib = float(row.get("vibration_mm_s", 0.0))
        rpm = float(row.get("rpm", 1500.0))
    except (TypeError, ValueError):
        return True, "warning", "sensor_anomaly"
    hits = [
        temp > TEMP_HIGH,
        vib > VIBRATION_HIGH,
        rpm < RPM_LOW or rpm > RPM_HIGH,
    ]
    n = sum(hits)
    if n == 0:
        return False, "info", "sensor_normal"
    if n >= 2 or temp > 95.0 or vib > 8.0:
        return True, "critical", "sensor_anomaly"
    return True, "warning", "sensor_anomaly"


def predict_batch(rows: list[dict]) -> list[bool]:
    return [predict(r)[0] for r in rows]


def evaluate(rows: list[dict]) -> dict:
    """Confusion matrix + precision/recall/F1/FPR/FNR on labeled rows."""
    tp = fp = tn = fn = 0
    for r in rows:
        actual = r.get("label") == "anomaly"
        pred = predict(r)[0]
        if actual and pred:
            tp += 1
        elif not actual and pred:
            fp += 1
        elif not actual and not pred:
            tn += 1
        else:
            fn += 1
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "model_version": MODEL_VERSION,
        "n": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "fnr": round(fn / (fn + tp), 4) if (fn + tp) else 0.0,
    }
