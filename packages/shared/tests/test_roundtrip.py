"""PG-003 golden DTO round-trip checks (stdlib only: json, hashlib, base64, re).

Run: `python -m pytest packages/shared/tests -q`
  or: `python packages/shared/tests/test_roundtrip.py`
"""
import base64
import hashlib
import json
import re
from pathlib import Path

SHARED = Path(__file__).resolve().parents[1]
FIX = SHARED / "fixtures"
SCHEMA = SHARED / "json-schema"

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
RES_RE = re.compile(r"^0x[0-9a-f]{64}$")
WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
INSIGHT_FIELDS = {"event_id", "event_type", "severity", "observed_at", "model_version"}
RAW_FORBIDDEN = {
    "temp_c", "vibration_mm_s", "rpm", "telemetry", "device_id",
    "signature_b64", "sequence", "issued_at", "resource_id",
    "gps", "coordinates", "score", "confidence", "explanation", "prompt",
}
AAD_FIELDS = {
    "schema_version", "delivery_id", "event_id", "resource_id",
    "recipient_wallet", "policy_version", "key_epoch",
}


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def load_fixture(name):
    raw = (FIX / name).read_bytes().decode("utf-8")
    body = raw[:-1] if raw.endswith("\n") else raw
    return body, json.loads(body)


def test_fixtures_are_canonical_json():
    for name in ("signed-telemetry-v1.json", "policy-manifest-v1.json",
                 "insight-v1.json", "envelope-v1.json", "policy-digest.json"):
        body, obj = load_fixture(name)
        assert body == canonical(obj).decode("utf-8"), f"{name} not canonical"


def test_policy_digest_roundtrip():
    _, manifest = load_fixture("policy-manifest-v1.json")
    _, digest_doc = load_fixture("policy-digest.json")
    assert manifest["allowed_fields"] == sorted(manifest["allowed_fields"])
    assert manifest["allowed_fields"] == sorted(INSIGHT_FIELDS)
    assert manifest["allowed_event_types"] == ["MACHINE_ANOMALY"]
    assert manifest["scope"] == "READ_INSIGHT"
    assert RES_RE.match(manifest["resource_id"])
    assert re.match(r"^0x[0-9a-f]{40}$",
                    manifest["recipient_wallet_lowercase"])
    expect = "0x" + hashlib.sha256(canonical(manifest)).hexdigest()
    assert digest_doc["policy_digest"] == expect


def test_insight_exactly_five_fields():
    _, insight = load_fixture("insight-v1.json")
    assert set(insight) == INSIGHT_FIELDS
    assert insight["event_type"] == "MACHINE_ANOMALY"
    assert insight["severity"] in ("LOW", "MEDIUM", "HIGH")
    assert UUID_RE.match(insight["event_id"])
    assert TS_RE.match(insight["observed_at"])
    assert not (set(insight) & RAW_FORBIDDEN)


def test_telemetry_ranges_and_key_shapes():
    _, msg = load_fixture("signed-telemetry-v1.json")
    assert msg["schema_version"] == 1
    assert UUID_RE.match(msg["device_id"])
    assert RES_RE.match(msg["resource_id"])
    assert isinstance(msg["sequence"], int) and msg["sequence"] > 0
    assert TS_RE.match(msg["issued_at"])
    t = msg["telemetry"]
    assert set(t) == {"temp_c", "vibration_mm_s", "rpm"}
    assert -40 <= t["temp_c"] <= 200
    assert 0 <= t["vibration_mm_s"] <= 100
    assert isinstance(t["rpm"], int) and 0 <= t["rpm"] <= 30000
    assert len(base64.b64decode(msg["signature_b64"])) == 64


def test_envelope_ciphertext_only_and_aad():
    _, env = load_fixture("envelope-v1.json")
    assert set(env) == {"delivery_id", "schema_version", "resource_id",
                        "recipient_wallet", "policy_version", "key_epoch",
                        "ephemeral_public_key_b64", "nonce_b64", "aad_b64",
                        "ciphertext_b64"}
    assert UUID_RE.match(env["delivery_id"])
    assert RES_RE.match(env["resource_id"])
    assert WALLET_RE.match(env["recipient_wallet"])
    assert len(base64.b64decode(env["ephemeral_public_key_b64"])) == 32
    assert len(base64.b64decode(env["nonce_b64"])) == 12
    assert len(base64.b64decode(env["ciphertext_b64"])) > 0
    aad = json.loads(base64.b64decode(env["aad_b64"]).decode("utf-8"))
    assert set(aad) == AAD_FIELDS
    for k in ("delivery_id", "resource_id", "recipient_wallet",
              "policy_version", "key_epoch", "schema_version"):
        assert aad[k] == env[k], f"AAD {k} mismatch"
    _, insight = load_fixture("insight-v1.json")
    assert aad["event_id"] == insight["event_id"]
    assert not (set(env) & RAW_FORBIDDEN - {"resource_id"})


def test_insight_schema_matches_fixture_contract():
    schema = json.loads((SCHEMA / "insight-v1.json").read_text())
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == INSIGHT_FIELDS
    assert set(schema["properties"]) == INSIGHT_FIELDS
    assert schema["properties"]["event_type"] == {"const": "MACHINE_ANOMALY"}


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"{len(tests)} passed")
