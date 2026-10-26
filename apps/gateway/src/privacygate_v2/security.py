"""Canonical encodings, password hashing, and the browser EnvelopeV2 contract."""

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str, length: int | None = None) -> bytes:
    result = base64.b64decode(value, validate=True)
    if b64(result) != value or (length is not None and len(result) != length):
        raise ValueError("Invalid encoding")
    return result


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    hashed = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())
    return f"scrypt$32768$8$1${b64(salt)}${b64(hashed)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$")
        if (algorithm, n, r, p) != ("scrypt", "32768", "8", "1"):
            return False
        Scrypt(salt=unb64(salt, 16), length=32, n=32768, r=8, p=1).verify(
            password.encode(), unb64(expected, 32)
        )
        return True
    except (ValueError, TypeError, InvalidKey):
        return False


INSIGHT_FIELDS = {"event_id", "event_type", "severity", "observed_at", "model_version"}


def encrypt_envelope(
    insight: dict,
    resource_id: str,
    recipient_id: str,
    policy_version: int,
    key: dict,
    delivery_id: str,
) -> dict:
    if (
        set(insight) != INSIGHT_FIELDS
        or insight["event_type"] != "MACHINE_ANOMALY"
        or insight["severity"] not in {"LOW", "MEDIUM", "HIGH"}
        or not all(isinstance(v, str) for v in insight.values())
    ):
        raise ValueError("Invalid insight")
    context = {
        "event_id": insight["event_id"],
        "key_epoch": policy_version,
        "key_version": key["key_version"],
        "policy_version": policy_version,
        "recipient_id": recipient_id,
        "resource_id": resource_id,
    }
    aad = canonical({"schema_version": 2, "delivery_id": delivery_id, **context})
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(
        X25519PublicKey.from_public_bytes(unb64(key["x25519_public_key_b64"], 32))
    )
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(32),
        info=b"privacygate-envelope-v2|" + canonical(context),
    ).derive(shared)
    nonce = os.urandom(12)
    return {
        "schema_version": 2,
        "delivery_id": delivery_id,
        "resource_id": resource_id,
        "recipient_id": recipient_id,
        "policy_version": policy_version,
        "key_version": key["key_version"],
        "key_epoch": policy_version,
        "ephemeral_public_key_b64": b64(ephemeral.public_key().public_bytes_raw()),
        "nonce_b64": b64(nonce),
        "aad_b64": b64(aad),
        "ciphertext_b64": b64(AESGCM(derived).encrypt(nonce, canonical(insight), aad)),
    }
