"""PG-011 canonical JSON + Ed25519 signing (PyNaCl, stdlib otherwise)."""
from __future__ import annotations

import base64
import json

from nacl.signing import SigningKey, VerifyKey


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def unsigned_of(msg: dict) -> dict:
    return {k: v for k, v in msg.items() if k != "signature_b64"}


def sign_message(signing_key: SigningKey, unsigned: dict) -> dict:
    msg = dict(unsigned)
    sig = signing_key.sign(canonical(unsigned)).signature
    msg["signature_b64"] = base64.b64encode(sig).decode("ascii")
    return msg


def verify_message(public_key_32: bytes, msg: dict) -> bool:
    try:
        sig = base64.b64decode(msg["signature_b64"])
        VerifyKey(public_key_32).verify(canonical(unsigned_of(msg)), sig)
        return True
    except Exception:
        return False


def b64_pubkey(signing_key: SigningKey) -> str:
    return base64.b64encode(bytes(signing_key.verify_key)).decode("ascii")
