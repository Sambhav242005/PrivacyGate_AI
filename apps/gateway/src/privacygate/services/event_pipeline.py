"""PG-016 pipeline: raw reading -> internal candidate -> strict InsightV1."""
from __future__ import annotations

from typing import Any

try:
    from apps.gateway.ai.inference import analyze_telemetry
except ImportError:  # running with apps/gateway itself on sys.path
    from ai.inference import analyze_telemetry  # type: ignore[no-redef]

from privacygate.domain.schemas import InsightV1
from privacygate.domain.serializer import serialize_candidate


def process_candidate(candidate: dict[str, Any]) -> InsightV1 | None:
    return serialize_candidate(candidate)


def process_reading(row: dict[str, Any], observed_at: str | None = None) -> InsightV1 | None:
    """Full step: inference candidate, then strict serializer."""
    return serialize_candidate(analyze_telemetry(row, observed_at))
