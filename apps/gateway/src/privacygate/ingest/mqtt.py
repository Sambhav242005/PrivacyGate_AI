"""PG-012 MQTT ingestion validation + PG-013 encrypted store write path.

Validates topic-device binding, schema/range, clock window, pinned-key
signature and per-device replay; persists AES-GCM ciphertext atomically.

Returns ``(http_status, body)`` with API.md error codes; never logs payloads.
"""
from __future__ import annotations

import base64
import binascii
import json
import time
from datetime import datetime, timezone
from typing import Any

from privacygate.domain.schemas import SignedTelemetryV1
from privacygate.ingest.signatures import canonical, unsigned_of, verify_message
from privacygate.security.crypto_store import build_aad, encrypt

MAX_PAYLOAD_BYTES = 4096
# API.md SPEC §7: ±30s clock window.
CLOCK_SKEW_S = 30
TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def parse_topic(topic: str) -> str | None:
    parts = topic.split("/")
    if len(parts) == 3 and parts[0] == "devices" and parts[2] == "telemetry" and parts[1]:
        return parts[1]
    return None


def _err(status: int, code: str, message: str) -> tuple[int, dict[str, Any]]:
    return status, {"error": {"code": code, "message": message}}


def _issued_unix(issued_at: str) -> float | None:
    try:
        return datetime.strptime(issued_at, TS_FMT).replace(
            tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def ingest_message(topic: str, payload: bytes, repo: Any,
                   data_key: bytes, now: float | None = None,
                   ) -> tuple[int, dict[str, Any]]:
    """Validate one MQTT message; on success store ciphertext. No plaintext logs."""
    if len(payload) > MAX_PAYLOAD_BYTES:
        return _err(400, "INVALID_INPUT", "payload exceeds 4096 bytes")
    try:
        msg = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _err(400, "INVALID_INPUT", "malformed JSON payload")
    if not isinstance(msg, dict):
        return _err(400, "INVALID_INPUT", "payload must be a JSON object")

    topic_device = parse_topic(topic)
    if topic_device is None:
        return _err(400, "INVALID_INPUT", "invalid topic")
    if msg.get("device_id") != topic_device:
        return _err(400, "INVALID_INPUT", "topic-device binding mismatch")

    try:
        reading = SignedTelemetryV1.model_validate(msg)
    except Exception:
        return _err(400, "INVALID_INPUT", "schema/range validation failed")

    device = repo.get_device(str(reading.device_id))
    if device is None or not device.get("active", True):
        return _err(401, "NOT_AUTHENTICATED", "unknown or inactive device")
    if str(reading.resource_id) != device["resource_id"]:
        return _err(400, "INVALID_INPUT", "device-resource binding mismatch")

    ts = _issued_unix(reading.issued_at)
    now_s = time.time() if now is None else now
    if ts is None or abs(now_s - ts) > CLOCK_SKEW_S:
        return _err(400, "INVALID_INPUT", "timestamp outside clock window")

    try:
        pinned = base64.b64decode(device["ed25519_public_key_b64"], validate=True)
    except (binascii.Error, ValueError):
        return _err(401, "NOT_AUTHENTICATED", "invalid pinned key")
    if not verify_message(pinned, msg):
        return _err(401, "NOT_AUTHENTICATED", "signature verification failed")

    aad = build_aad(device_id=str(reading.device_id),
                    sequence=reading.sequence,
                    resource_id=str(reading.resource_id))
    nonce, ciphertext = encrypt(data_key, aad, canonical(unsigned_of(msg)))
    try:
        record = repo.save_reading(
            device_id=str(reading.device_id), sequence=reading.sequence,
            issued_at=reading.issued_at, nonce=nonce, ciphertext=ciphertext)
    except (ValueError, KeyError):
        return _err(409, "REPLAY_DETECTED", "duplicate or stale sequence")
    return 200, {"device_id": record["device_id"], "sequence": record["sequence"]}
