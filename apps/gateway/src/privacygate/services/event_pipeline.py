"""PG-016 pipeline: raw reading -> internal candidate -> strict InsightV1.

Reference only for the AI side: inference/baseline modules are owned by
the gateway/AI workstream and intentionally NOT imported at module load.
"""
from __future__ import annotations

from typing import Any

from privacygate.domain.schemas import InsightV1
from privacygate.domain.serializer import serialize_candidate


def process_candidate(candidate: dict[str, Any]) -> InsightV1 | None:
    return serialize_candidate(candidate)


def _analyze(row: dict[str, Any], observed_at: str | None) -> dict[str, Any]:
    for mod in ("apps.gateway.ai.inference", "ai.inference"):
        try:
            m = __import__(mod, fromlist=["analyze_telemetry"])
            return m.analyze_telemetry(row, observed_at)
        except ImportError:
            continue
    # Fallback: baseline.py has no relative imports, load by path.
    import importlib.util
    from pathlib import Path
    base = Path(__file__).resolve().parents[3] / "ai" / "baseline.py"
    spec = importlib.util.spec_from_file_location("pg_baseline", base)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    import uuid as _uuid
    from datetime import datetime, timezone
    is_anomaly, severity, event_type = mod.predict(row)
    return {"event_id": str(_uuid.uuid4()), "event_type": event_type,
            "severity": severity,
            "observed_at": observed_at or datetime.now(timezone.utc).isoformat(
                timespec="milliseconds").replace("+00:00", "Z"),
            "model_version": mod.MODEL_VERSION, "is_anomaly": is_anomaly}


def process_reading(row: dict[str, Any], observed_at: str | None = None) -> InsightV1 | None:
    """Full step: baseline/inference candidate, then strict serializer."""
    return serialize_candidate(_analyze(row, observed_at))
