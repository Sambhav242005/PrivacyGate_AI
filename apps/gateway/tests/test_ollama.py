"""Ollama backend tests: monkeypatched client, no live server needed."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from apps.gateway.ai import inference, ollama
from apps.gateway.ai.baseline import MODEL_VERSION
from apps.gateway.ai.ollama import OllamaConfig, build_prompt, parse_output


def _fake_openai_module(payload=None, exc=None):
    import types

    mod = types.ModuleType("openai")

    class _Msg:
        def __init__(self, content):
            self.content = content

    class _Choice:
        def __init__(self, content):
            self.message = _Msg(content)

    class _Resp:
        def __init__(self, content):
            self.choices = [_Choice(content)]

    class _Completions:
        def __init__(self, outer):
            self._outer = outer

        def create(self, **kwargs):
            self._outer["kwargs"] = kwargs
            if exc is not None:
                raise exc
            return _Resp(payload)

    class _Chat:
        def __init__(self, outer):
            self.completions = _Completions(outer)

    class OpenAI:
        def __init__(self, **kwargs):
            outer["init"] = kwargs
            self.chat = _Chat(outer)
            self._outer = outer

        @property
        def models(self):
            class _M:
                @staticmethod
                def list():
                    if exc is not None:
                        raise exc
                    return []

            return _M()

    outer = {"kwargs": None, "init": None}
    mod.OpenAI = OpenAI
    mod._outer = outer
    return mod


def test_parse_json_only():
    sig = parse_output('{"anomaly": true, "severity": "HIGH", "confidence": 0.9}')
    assert sig == {"anomaly": True, "severity": "HIGH", "confidence": 0.9}


def test_parse_strips_fences():
    sig = parse_output('```json\n{"anomaly": false, "severity": "LOW", "confidence": 0.1}\n```')
    assert sig["anomaly"] is False and sig["severity"] == "LOW"


def test_parse_rejects_invalid_enum():
    with pytest.raises(ValueError):
        parse_output('{"anomaly": true, "severity": "CRITICAL", "confidence": 0.9}')


def test_parse_rejects_extra_keys():
    with pytest.raises(ValueError):
        parse_output('{"anomaly": true, "severity": "HIGH", "confidence": 0.9, "explanation": "x"}')


def test_prompt_contains_no_wallet_or_key_material():
    p = build_prompt({"temp_c": 70.0, "vibration_mm_s": 2.0, "rpm": 1500.0,
                      "wallet": "0xabc", "device_key": "secret"})
    assert "0xabc" not in p and "secret" not in p and "wallet" not in p
    assert "temp_c" in p


def test_inference_uses_ollama_when_ok(monkeypatch):
    fake = _fake_openai_module('{"anomaly": true, "severity": "HIGH", "confidence": 0.95}')
    monkeypatch.setitem(sys.modules, "openai", fake)
    cand = inference.analyze_telemetry({"temp_c": 65.0, "vibration_mm_s": 2.0, "rpm": 1500.0})
    assert cand["is_anomaly"] is True
    assert cand["model_version"].startswith("ollama:")
    assert "confidence" not in cand  # never forwarded to serializer


def test_inference_falls_back_on_connection_error(monkeypatch):
    fake = _fake_openai_module(exc=ConnectionError("down"))
    monkeypatch.setitem(sys.modules, "openai", fake)
    cand = inference.analyze_telemetry({"temp_c": 65.0, "vibration_mm_s": 2.0, "rpm": 1500.0})
    assert cand["model_version"] == MODEL_VERSION
    assert cand["is_anomaly"] is False


def test_inference_falls_back_on_invalid_enum(monkeypatch):
    fake = _fake_openai_module('{"anomaly": true, "severity": "BOGUS", "confidence": 0.5}')
    monkeypatch.setitem(sys.modules, "openai", fake)
    cand = inference.analyze_telemetry({"temp_c": 100.0, "vibration_mm_s": 9.0, "rpm": 900.0})
    assert cand["model_version"] == MODEL_VERSION
    assert cand["is_anomaly"] is True  # baseline catches blatant anomaly


def test_get_backend_reports_ollama_or_rule(monkeypatch):
    fake = _fake_openai_module()
    monkeypatch.setitem(sys.modules, "openai", fake)
    b = inference.get_backend()
    assert b.startswith("ollama:") or b == MODEL_VERSION


def test_config_defaults():
    for k in ("OLLAMA_BASE_URL", "OLLAMA_MODEL", "OLLAMA_API_KEY"):
        os.environ.pop(k, None)
    cfg = OllamaConfig()
    assert cfg.base_url == "http://127.0.0.1:11434/v1"
    assert cfg.api_key == "ollama"
    assert isinstance(cfg.model, str) and cfg.model


@pytest.mark.skipif(os.environ.get("OLLAMA_LIVE") != "1", reason="live Ollama test; set OLLAMA_LIVE=1")
def test_live_ollama():
    import socket
    from urllib.parse import urlparse

    cfg = OllamaConfig()
    host = urlparse(cfg.base_url).hostname or "127.0.0.1"
    port = urlparse(cfg.base_url).port or 11434
    s = socket.create_connection((host, port), timeout=2)
    s.close()
    sig = ollama.analyze_with_ollama({"temp_c": 65.0, "vibration_mm_s": 2.0, "rpm": 1500.0}, cfg)
    assert sig["severity"] in ("LOW", "MEDIUM", "HIGH")
