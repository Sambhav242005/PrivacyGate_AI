"""Inference wrapper: Ollama first, rule baseline fallback.

MVP has zero extra deps for detection (stdlib baseline); the Ollama path
uses the OpenAI-compatible client ONLY with an Ollama base_url override.
AI never touches chain/auth/storage: numeric telemetry in, candidate out.
The model proposes; domain/serializer.py decides (confidence never forwarded).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from . import baseline

log = logging.getLogger(__name__)

MODEL_VERSION = baseline.MODEL_VERSION
IF_MODEL_VERSION = "isolation-forest-v1"

_forest = None
try:  # optional; stdlib baseline remains a fallback
    from sklearn.ensemble import IsolationForest  # type: ignore

    _forest = IsolationForest()
except ImportError:
    _forest = None

_SEV_TO_BASELINE = {"LOW": "info", "MEDIUM": "warning", "HIGH": "critical"}


def get_backend() -> str:
    """Report 'ollama:MODEL' when Ollama reachable, else rule/IF version."""
    try:
        from .ollama import OllamaConfig

        cfg = OllamaConfig()
        from openai import OpenAI

        client = OpenAI(base_url=cfg.base_url, api_key=cfg.api_key, timeout=2.0)
        client.models.list()
        return f"ollama:{cfg.model}"
    except Exception:
        return IF_MODEL_VERSION if _forest is not None else MODEL_VERSION


def _baseline_candidate(row: dict, observed_at: str | None) -> dict:
    is_anomaly, severity, event_type = baseline.predict(row)
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "severity": severity,
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "model_version": MODEL_VERSION,
        "is_anomaly": is_anomaly,
    }


def analyze_telemetry(row: dict, observed_at: str | None = None) -> dict:
    """Return candidate insight dict (internal; policy gate trims to 5 fields).

    Tries Ollama first; falls back to rule baseline on connection/timeout/
    parse failure (logged, never raised on the detection path).
    """
    try:
        from .ollama import OllamaConfig, analyze_with_ollama

        cfg = OllamaConfig()
        signal = analyze_with_ollama(row, cfg)
        sev = _SEV_TO_BASELINE[signal["severity"]]
        is_anomaly = signal["anomaly"]
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "sensor_anomaly" if is_anomaly else "sensor_normal",
            "severity": sev,
            "observed_at": observed_at or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "model_version": f"ollama:{cfg.model}",
            "is_anomaly": is_anomaly,
        }
    except Exception as e:
        log.warning("ollama fallback to baseline: %s", type(e).__name__)
        return _baseline_candidate(row, observed_at)
