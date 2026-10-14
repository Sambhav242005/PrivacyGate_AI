"""PG-016 strict candidate -> InsightV1 serializer.

Builds a NEW InsightV1 from allowed values only; never serializes the
untrusted model object. Exactly five fields per DATA_MODEL.md.
"""
from __future__ import annotations

import json
from typing import Any

from .schemas import INSIGHT_FIELDS, InsightV1

ALLOWED_FIELDS = frozenset(INSIGHT_FIELDS)
# Internal-only key carried from inference; never part of InsightV1.
_INTERNAL_KEYS = frozenset({"is_anomaly"})

_SEVERITY_MAP = {
    "critical": "HIGH",
    "warning": "MEDIUM",
    "info": "LOW",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

_EVENT_MAP = {
    "sensor_anomaly": "MACHINE_ANOMALY",
    "MACHINE_ANOMALY": "MACHINE_ANOMALY",
}

# T-06 leakage scan markers: quoted JSON keys that must never appear in a
# released insight payload. Quoted form avoids false positives on values.
LEAK_MARKERS = (
    '"temp_c"', '"vibration_mm_s"', '"rpm"', '"device_id"', '"resource_id"',
    '"telemetry"', '"explanation"', '"prompt"', '"confidence"', '"score"',
    '"gps"', '"latitude"', '"longitude"', '"signature_b64"',
)


def serialize_candidate(candidate: dict[str, Any]) -> InsightV1 | None:
    """Map an internal AI candidate dict to InsightV1.

    Returns None for non-anomalous candidates (no event). Raises ValueError
    on any forbidden/arbitrary field, unknown severity/event, or bad shape.
    """
    if not isinstance(candidate, dict):
        raise ValueError("candidate must be a dict")
    for key in candidate:
        if key in _INTERNAL_KEYS:
            continue
        if key not in ALLOWED_FIELDS:
            raise ValueError(f"forbidden field: {key}")
    if "is_anomaly" not in candidate:
        raise ValueError("candidate missing is_anomaly flag")
    if not candidate["is_anomaly"]:
        return None
    try:
        event_type = _EVENT_MAP[candidate["event_type"]]
    except KeyError:
        raise ValueError(f"unsupported event_type: {candidate.get('event_type')!r}") from None
    try:
        severity = _SEVERITY_MAP[str(candidate["severity"])]
    except KeyError:
        raise ValueError(f"unsupported severity: {candidate.get('severity')!r}") from None
    insight = InsightV1(
        event_id=str(candidate["event_id"]),
        event_type=event_type,
        severity=severity,
        observed_at=str(candidate["observed_at"]),
        model_version=str(candidate["model_version"]),
    )
    assert_no_leakage(insight)
    return insight


def assert_no_leakage(insight: InsightV1 | dict[str, Any]) -> None:
    """T-06: fail if raw telemetry/explanation-like keys leak into payload."""
    if isinstance(insight, InsightV1):
        blob = json.dumps(insight.model_dump(mode="json"), sort_keys=True)
    else:
        blob = json.dumps(insight, sort_keys=True, default=str)
    for marker in LEAK_MARKERS:
        if marker in blob:
            raise ValueError(f"leakage marker in insight payload: {marker}")


def insight_canonical_bytes(insight: InsightV1) -> bytes:
    """Canonical UTF-8 bytes of InsightV1 (envelope plaintext)."""
    return json.dumps(
        insight.model_dump(mode="json"), sort_keys=True,
        separators=(",", ":")).encode("utf-8")
