"""PG-012 Ed25519 verification against pinned device public key (PyNaCl).

Mirrors apps/simulator signing semantics; simulator is reference only.
Signature covers canonical JSON of all fields except ``signature_b64``.
"""
from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


def canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def unsigned_of(msg: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in msg.items() if k != "signature_b64"}


def verify_message(public_key_32: bytes, msg: dict[str, Any]) -> bool:
    """Verify Ed25519 signature with pinned 32-byte pubkey. Fail closed."""
    try:
        if len(public_key_32) != 32:
            return False
        sig = base64.b64decode(msg["signature_b64"], validate=True)
        VerifyKey(public_key_32).verify(canonical(unsigned_of(msg)), sig)
        return True
    except (KeyError, binascii.Error, BadSignatureError, ValueError):
        return False
