"""Ollama backend via OpenAI-compatible client (base_url override only).

Scope: numeric telemetry in, candidate signal out. NEVER touches
chain/auth/storage. Model proposes; domain/serializer.py decides.
Confidence is consumed locally and NEVER forwarded to the serializer
(serializer forbids it as a leak marker).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "gemma4:31b-cloud"  # env-overridable; "gemm4:31b-cloud" typo also works via env
DEFAULT_API_KEY = "ollama"
DEFAULT_TIMEOUT = 10.0

ALLOWED_SEVERITIES = ("LOW", "MEDIUM", "HIGH")

SYSTEM_PROMPT = (
    "You are a strict industrial-sensor anomaly classifier. "
    "Input is numeric telemetry only: temp_c (float), vibration_mm_s (float), rpm (float). "
    "Reply with JSON ONLY, no markdown, no explanation, exactly this schema: "
    '{"anomaly": bool, "severity": "LOW"|"MEDIUM"|"HIGH", "confidence": float 0..1}. '
    "Rules: severity LOW when anomaly=false; MEDIUM or HIGH when anomaly=true. "
    "Output nothing else."
)


@dataclass
class OllamaConfig:
    base_url: str = field(default_factory=lambda: os.environ.get("OLLAMA_BASE_URL", DEFAULT_BASE_URL))
    model: str = field(default_factory=lambda: os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL))
    api_key: str = field(default_factory=lambda: os.environ.get("OLLAMA_API_KEY", DEFAULT_API_KEY))
    timeout: float = DEFAULT_TIMEOUT


def build_prompt(telemetry: dict) -> str:
    """Numeric-only user prompt. Drops any wallet/key material keys."""
    try:
        temp = float(telemetry.get("temp_c", 0.0))
        vib = float(telemetry.get("vibration_mm_s", 0.0))
        rpm = float(telemetry.get("rpm", 1500.0))
    except (TypeError, ValueError):
        temp, vib, rpm = 0.0, 0.0, 1500.0
    return json.dumps({"temp_c": temp, "vibration_mm_s": vib, "rpm": rpm})


def parse_output(text: str) -> dict:
    """Strict parse: strip fences, extract JSON, validate enums/ranges. Raises ValueError."""
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON object in model output")
    try:
        obj = json.loads(t[start : end + 1])
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from None
    if not isinstance(obj, dict):
        raise ValueError("output must be a JSON object")
    if set(obj) != {"anomaly", "severity", "confidence"}:
        raise ValueError(f"unexpected keys: {sorted(obj)}")
    if not isinstance(obj["anomaly"], bool):
        raise ValueError("anomaly must be bool")
    if obj["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError(f"bad severity: {obj['severity']!r}")
    conf = obj["confidence"]
    if not isinstance(conf, (int, float)) or isinstance(conf, bool):
        raise ValueError("confidence must be a number")
    if not 0.0 <= float(conf) <= 1.0:
        raise ValueError("confidence out of range")
    if not obj["anomaly"] and obj["severity"] != "LOW":
        raise ValueError("non-anomaly must be LOW")
    return {"anomaly": obj["anomaly"], "severity": obj["severity"], "confidence": float(conf)}


def analyze_with_ollama(telemetry: dict, config: OllamaConfig | None = None) -> dict:
    """Return candidate signal dict. Raises on connection/timeout/parse failure (caller falls back)."""
    from openai import OpenAI  # OpenAI-compatible client used ONLY for Ollama base_url override

    cfg = config or OllamaConfig()
    client = OpenAI(base_url=cfg.base_url, api_key=cfg.api_key, timeout=cfg.timeout)
    resp = client.chat.completions.create(
        model=cfg.model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(telemetry)},
        ],
        temperature=0,
    )
    text = resp.choices[0].message.content or ""
    return parse_output(text)
