"""PG-014 synthetic dataset generator (stdlib only, seeded, reproducible).

Distributions (documented, versioned here):
- normal:  temp_c ~ N(65, 3), vibration_mm_s ~ N(2.0, 0.5), rpm ~ N(1500, 50)
- anomaly: at least one of temp_c in [85, 110], vibration_mm_s in [6, 12],
  rpm in [800, 1100] or [2000, 2400] (uniform ranges, Gaussian jitter).

License note: synthetic data only, no real telemetry, free to use for tests.
"""

from __future__ import annotations

import csv
import random

DATASET_VERSION = "synth-v1"
DEFAULT_SEED = 42

FIELDNAMES = ("temp_c", "vibration_mm_s", "rpm", "label")

LABEL_NORMAL = "normal"
LABEL_ANOMALY = "anomaly"


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def generate_row(rng: random.Random, label: str) -> dict:
    if label == LABEL_ANOMALY:
        mode = rng.choice(("temp", "vibration", "rpm"))
        if mode == "temp":
            temp = rng.uniform(85.0, 110.0)
            vib = abs(rng.gauss(2.0, 0.5))
            rpm = rng.gauss(1500.0, 50.0)
        elif mode == "vibration":
            temp = rng.gauss(65.0, 3.0)
            vib = rng.uniform(6.0, 12.0)
            rpm = rng.gauss(1500.0, 50.0)
        else:
            temp = rng.gauss(65.0, 3.0)
            vib = abs(rng.gauss(2.0, 0.5))
            rpm = rng.choice((rng.uniform(800.0, 1100.0), rng.uniform(2000.0, 2400.0)))
        return {
            "temp_c": round(_clamp(temp, -50.0, 150.0), 2),
            "vibration_mm_s": round(_clamp(vib, 0.0, 30.0), 2),
            "rpm": round(_clamp(rpm, 0.0, 5000.0), 1),
            "label": LABEL_ANOMALY,
        }
    temp = rng.gauss(65.0, 3.0)
    vib = abs(rng.gauss(2.0, 0.5))
    rpm = rng.gauss(1500.0, 50.0)
    return {
        "temp_c": round(_clamp(temp, -50.0, 150.0), 2),
        "vibration_mm_s": round(_clamp(vib, 0.0, 30.0), 2),
        "rpm": round(_clamp(rpm, 0.0, 5000.0), 1),
        "label": LABEL_NORMAL,
    }


def generate_split(n_normal: int, n_anomaly: int, seed: int) -> list[dict]:
    """One reproducible split. Rows shuffled with the same seed."""
    rng = random.Random(seed)
    rows = [generate_row(rng, LABEL_NORMAL) for _ in range(n_normal)]
    rows += [generate_row(rng, LABEL_ANOMALY) for _ in range(n_anomaly)]
    rng.shuffle(rows)
    return rows


def generate_dataset(
    train_normal: int = 800,
    train_anomaly: int = 100,
    test_normal: int = 200,
    test_anomaly: int = 100,
    seed: int = DEFAULT_SEED,
) -> tuple[list[dict], list[dict]]:
    """Disjoint train/test splits; test uses seed+1 so no shared RNG stream."""
    train = generate_split(train_normal, train_anomaly, seed)
    test = generate_split(test_normal, test_anomaly, seed + 1)
    return train, test


def to_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(FIELDNAMES))
        w.writeheader()
        w.writerows(rows)


def from_csv(path: str) -> list[dict]:
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        out.append(
            {
                "temp_c": float(r["temp_c"]),
                "vibration_mm_s": float(r["vibration_mm_s"]),
                "rpm": float(r["rpm"]),
                "label": r["label"],
            }
        )
    return out


if __name__ == "__main__":  # ponytail: manual demo path, no framework
    import os

    os.makedirs("var", exist_ok=True)
    train, test = generate_dataset()
    to_csv(train, "var/synthetic_train.csv")
    to_csv(test, "var/synthetic_test.csv")
    print(f"wrote var/synthetic_train.csv ({len(train)}) var/synthetic_test.csv ({len(test)}) seed={DEFAULT_SEED}")
