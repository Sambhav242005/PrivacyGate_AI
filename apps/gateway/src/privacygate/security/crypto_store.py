"""PG-013 AES-256-GCM telemetry payload encryption (``cryptography`` lib).

Column/payload encryption only, not full-file encryption. Raw readings are
encrypted application-side before SQLite; decrypted only for the owner path.
Never log plaintext, keys, nonces or ciphertext.
"""
from __future__ import annotations

import json
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12
KEY_BYTES = 32


def load_data_key(env: str = "GATEWAY_DATA_KEY_B64") -> bytes:
    """Load 32-byte app data key from base64 env var. Raises on misconfig."""
    import base64

    raw_b64 = os.environ.get(env, "")
    try:
        key = base64.b64decode(raw_b64, validate=True)
    except Exception as e:
        raise ValueError(f"invalid {env}: not base64") from e
    if len(key) != KEY_BYTES:
        raise ValueError(f"invalid {env}: want 32 bytes, got {len(key)}")
    return key


def generate_data_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def build_aad(device_id: str, sequence: int, resource_id: str,
              schema_version: int = 1) -> bytes:
    aad = {"device_id": device_id, "resource_id": resource_id,
           "schema_version": schema_version, "sequence": sequence}
    return json.dumps(aad, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def encrypt(key: bytes, aad: bytes, plaintext: bytes,
            nonce: bytes | None = None) -> tuple[bytes, bytes]:
    if len(key) != KEY_BYTES:
        raise ValueError("data key must be 32 bytes")
    nonce = secrets.token_bytes(NONCE_BYTES) if nonce is None else nonce
    if len(nonce) != NONCE_BYTES:
        raise ValueError("nonce must be 12 bytes")
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("bad key/nonce length")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def encrypt_reading(key: bytes, unsigned_msg: dict[str, Any]) -> tuple[bytes, bytes, bytes]:
    """Encrypt canonical unsigned reading; returns (nonce, ciphertext, aad)."""
    aad = build_aad(device_id=str(unsigned_msg["device_id"]),
                    sequence=int(unsigned_msg["sequence"]),
                    resource_id=str(unsigned_msg["resource_id"]),
                    schema_version=int(unsigned_msg.get("schema_version", 1)))
    canonical = json.dumps(unsigned_msg, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    nonce, ciphertext = encrypt(key, aad, canonical)
    return nonce, ciphertext, aad


def decrypt_reading(key: bytes, nonce: bytes, aad: bytes,
                    ciphertext: bytes) -> dict[str, Any]:
    return json.loads(decrypt(key, nonce, aad, ciphertext).decode("utf-8"))
