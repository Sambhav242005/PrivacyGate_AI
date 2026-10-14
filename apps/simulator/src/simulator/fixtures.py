"""PG-011 seeded deterministic sensor traces + invalid fixture modes."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from nacl.signing import SigningKey

from simulator.signing import sign_message

DEFAULT_DEVICE_ID = "30ad1113-88be-44fd-90fd-683d0a3dd7b0"
DEFAULT_RESOURCE_ID = "0x" + "aa" * 32
BASE_TIME = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)


def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def generate_trace(
    seed: int,
    count: int,
    device_id: str = DEFAULT_DEVICE_ID,
    resource_id: str = DEFAULT_RESOURCE_ID,
    mode: str = "normal",  # "normal" | "anomaly"
    start_seq: int = 1,
    base_time: datetime = BASE_TIME,
    step_s: float = 1.0,
) -> list[dict]:
    """Deterministic unsigned messages (no signature). Monotonic seq."""
    rng = random.Random(seed)
    out: list[dict] = []
    for i in range(count):
        anomalous = mode == "anomaly" and i >= count // 2
        temp = round(rng.gauss(70.0, 2.0) + (23.0 if anomalous else 0.0), 1)
        vib = round(max(0.0, rng.gauss(2.0, 0.4) + (5.0 if anomalous else 0.0)), 1)
        rpm = int(rng.gauss(1450, 15) + (60 if anomalous else 0))
        temp = min(200.0, max(-40.0, temp))
        vib = min(100.0, vib)
        rpm = min(30000, max(0, rpm))
        out.append(
            {
                "schema_version": 1,
                "device_id": device_id,
                "resource_id": resource_id,
                "sequence": start_seq + i,
                "issued_at": fmt_ts(base_time + timedelta(seconds=i * step_s)),
                "telemetry": {"temp_c": temp, "vibration_mm_s": vib, "rpm": rpm},
            }
        )
    return out


def sign_trace(trace: list[dict], signing_key: SigningKey) -> list[dict]:
    return [sign_message(signing_key, m) for m in trace]


def generate_signed(
    seed: int, count: int, signing_key: SigningKey, **kw
) -> list[dict]:
    return sign_trace(generate_trace(seed, count, **kw), signing_key)


def make_invalid(messages: list[dict], kind: str) -> list[dict]:
    """Return mutated copy: tamper | replay | expired. Differs from input."""
    import copy

    msgs = copy.deepcopy(messages)
    if kind == "tamper":
        # Modify telemetry after signing -> signature no longer verifies.
        msgs[-1]["telemetry"]["temp_c"] = round(msgs[-1]["telemetry"]["temp_c"] + 10.0, 1)
    elif kind == "replay":
        # Reuse an earlier sequence number -> replay/monotonic violation.
        if len(msgs) > 1:
            msgs[-1]["sequence"] = msgs[0]["sequence"]
        else:
            msgs[-1]["sequence"] = msgs[-1]["sequence"]  # single msg: keep, still differs?
            msgs.append(copy.deepcopy(msgs[-1]))
    elif kind == "expired":
        # Shift timestamp far outside ±30s skew window -> stale/future.
        old = datetime.strptime(msgs[-1]["issued_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
        msgs[-1]["issued_at"] = fmt_ts(old - timedelta(minutes=10))
    else:
        raise ValueError(f"unknown invalid kind: {kind}")
    return msgs
