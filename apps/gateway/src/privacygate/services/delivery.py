"""PG-032 policy-checked dispatch + encrypted queue (ciphertext only).

Flow per delivery: fresh chain authorize() -> key lookup -> envelope
encrypt (ephemeral X25519 + HKDF-SHA256 + AES-256-GCM, mature
`cryptography` lib) -> append ciphertext record. Revoked/expired grants,
digest mismatch, missing keys, and stale key epochs all block BEFORE any
crypto. The queue stores ciphertext + metadata only; plaintext InsightV1
bytes exist transiently inside dispatch() and never persist.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import time
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from privacygate.chain.permissions import PolicyDenied, authorize
from privacygate.domain.schemas import InsightV1

SCHEMA_VERSION = 1
# DESIGN.md section 7: info = b"privacygate-envelope-v1|" + canonical JSON of
# {event_id, key_epoch, policy_version, recipient_wallet, resource_id},
# salt=None (web passes 32 zero bytes, the RFC 5869 equivalent).
_HKDF_DOMAIN = b"privacygate-envelope-v1|"
WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
RES_RE = re.compile(r"^0x[0-9a-f]{64}$")


class KeyNotRegistered(Exception):
    pass


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64d(value: str, nbytes: int, name: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid {name}: {e}") from e
    if len(raw) != nbytes:
        raise ValueError(f"{name} must be {nbytes} bytes, got {len(raw)}")
    return raw


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


_AAD_FIELDS = frozenset((
    "schema_version", "delivery_id", "event_id", "resource_id",
    "recipient_wallet", "policy_version", "key_epoch",
))


def _hkdf_info(
    *,
    recipient_wallet: str,
    resource_id: str,
    event_id: str,
    policy_version: int,
    key_epoch: int,
) -> bytes:
    return _HKDF_DOMAIN + canonical({
        "event_id": str(event_id),
        "key_epoch": int(key_epoch),
        "policy_version": int(policy_version),
        "recipient_wallet": recipient_wallet.lower(),
        "resource_id": resource_id,
    })


def encrypt_envelope(
    insight: InsightV1,
    recipient_pub_b64: str,
    *,
    resource_id: str,
    recipient_wallet: str,
    policy_version: int,
    key_epoch: int,
    delivery_id: str | None = None,
) -> dict[str, object]:
    peer = X25519PublicKey.from_public_bytes(_b64d(recipient_pub_b64, 32, "recipient key"))
    eph_priv = X25519PrivateKey.generate()
    shared = eph_priv.exchange(peer)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_hkdf_info(
                   recipient_wallet=recipient_wallet,
                   resource_id=resource_id,
                   event_id=str(insight.event_id),
                   policy_version=int(policy_version),
                   key_epoch=int(key_epoch))).derive(shared)
    nonce = os.urandom(12)
    did = delivery_id or str(uuid.uuid4())
    aad_obj = {"delivery_id": did, "event_id": str(insight.event_id),
               "key_epoch": int(key_epoch),
               "policy_version": int(policy_version),
               "recipient_wallet": recipient_wallet.lower(),
               "resource_id": resource_id, "schema_version": SCHEMA_VERSION}
    aad = canonical(aad_obj)
    from privacygate.domain.serializer import insight_canonical_bytes
    ct = AESGCM(key).encrypt(nonce, insight_canonical_bytes(insight), aad)
    return {"delivery_id": did, "schema_version": SCHEMA_VERSION,
            "resource_id": resource_id,
            "recipient_wallet": recipient_wallet.lower(),
            "policy_version": int(policy_version), "key_epoch": int(key_epoch),
            "ephemeral_public_key_b64": _b64e(
                eph_priv.public_key().public_bytes_raw()),
            "nonce_b64": _b64e(nonce), "aad_b64": _b64e(aad), "ciphertext_b64": _b64e(ct)}


def decrypt_envelope(envelope: dict, recipient_priv_b64: str) -> InsightV1:
    """Client-side reference decryption (tests/subscriber app)."""
    try:
        priv = X25519PrivateKey.from_private_bytes(_b64d(recipient_priv_b64, 32, "private key"))
        peer = X25519PublicKey.from_public_bytes(
            _b64d(str(envelope["ephemeral_public_key_b64"]), 32, "ephemeral key"))
        nonce = _b64d(str(envelope["nonce_b64"]), 12, "nonce")
        try:
            aad = base64.b64decode(str(envelope["aad_b64"]), validate=True)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"invalid aad: {e}") from e
        try:
            ct = base64.b64decode(str(envelope["ciphertext_b64"]), validate=True)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"invalid ciphertext: {e}") from e
        if not ct:
            raise ValueError("empty ciphertext")
        aad_obj = json.loads(aad.decode("utf-8"))
        if not isinstance(aad_obj, dict) or set(aad_obj) != _AAD_FIELDS:
            raise ValueError("AAD fields mismatch")
        # AAD must mirror envelope header exactly (binds delivery context).
        for field in ("schema_version", "delivery_id", "resource_id",
                      "recipient_wallet", "policy_version", "key_epoch"):
            if aad_obj[field] != envelope[field]:
                raise ValueError(f"AAD {field} mismatch")
        if int(aad_obj["schema_version"]) != SCHEMA_VERSION:
            raise ValueError("unsupported schema_version")
        expected_aad = canonical({
            "schema_version": SCHEMA_VERSION,
            "delivery_id": str(aad_obj["delivery_id"]),
            "event_id": str(aad_obj["event_id"]),
            "resource_id": str(aad_obj["resource_id"]),
            "recipient_wallet": str(aad_obj["recipient_wallet"]),
            "policy_version": int(aad_obj["policy_version"]),
            "key_epoch": int(aad_obj["key_epoch"]),
        })
        if expected_aad != aad:
            raise ValueError("AAD encoding mismatch")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=_hkdf_info(
                       recipient_wallet=str(aad_obj["recipient_wallet"]),
                       resource_id=str(aad_obj["resource_id"]),
                       event_id=str(aad_obj["event_id"]),
                       policy_version=int(aad_obj["policy_version"]),
                       key_epoch=int(aad_obj["key_epoch"]))).derive(
                       priv.exchange(peer))
        pt = AESGCM(key).decrypt(nonce, ct, aad)
        insight = InsightV1.model_validate_json(pt)
        if str(insight.event_id) != str(aad_obj["event_id"]):
            raise ValueError("AAD event_id mismatch after decrypt")
        return insight
    except (InvalidTag, ValueError) as e:
        raise ValueError(f"envelope decrypt failed: {e}") from e


def scan_no_plaintext(records: list[dict], forbidden_terms: list[str]) -> None:
    """Assert no forbidden plaintext (raw readings, explanations) in queue."""
    blob = json.dumps(records, default=str)
    for term in forbidden_terms:
        if term in blob:
            raise ValueError(f"plaintext leak in queue: {term!r}")


class DeliveryQueue:
    """In-memory ciphertext queue + key/epoch registry (skeleton store)."""

    def __init__(self) -> None:
        self.items: list[dict] = []
        self.keys: dict[str, dict] = {}
        self.epochs: dict[tuple[str, str], int] = {}

    # -- recipient keys (PG-030 skeleton) --
    def register_key(self, wallet: str, pub_b64: str) -> dict[str, str]:
        if not WALLET_RE.match(wallet or ""):
            raise ValueError("invalid wallet address")
        _b64d(pub_b64, 32, "x25519 key")
        w = wallet.lower()
        rotated = w in self.keys and self.keys[w]["x25519_public_key_b64"] != pub_b64
        self.keys[w] = {"wallet_address": w, "key_id": self.keys.get(w, {}).get(
            "key_id", str(uuid.uuid4())), "x25519_public_key_b64": pub_b64,
            "registered_at": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())}
        if rotated:
            for (res, rec) in [k for k in self.epochs if k[1] == w]:
                self.epochs[res, rec] += 1
            for it in self.items:
                if it["envelope"]["recipient_wallet"] == w and it["invalidated_at"] is None:
                    it["invalidated_at"] = self.keys[w]["registered_at"]
        return self.keys[w]

    def current_epoch(self, resource_id: str, recipient_wallet: str) -> int:
        return self.epochs.get((resource_id, recipient_wallet.lower()), 0)

    def invalidate_recipient(self, resource_id: str, recipient_wallet: str) -> int:
        w = recipient_wallet.lower()
        self.epochs[(resource_id, w)] = self.current_epoch(resource_id, w) + 1
        now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        for it in self.items:
            env = it["envelope"]
            if (env["resource_id"] == resource_id and env["recipient_wallet"] == w
                    and it["invalidated_at"] is None):
                it["invalidated_at"] = now
        return self.epochs[(resource_id, w)]

    # -- dispatch --
    def dispatch(
        self,
        *,
        insight: InsightV1,
        resource_id: str,
        recipient_wallet: str,
        policy_id: str,
        policy_digest: str,
        policy_version: int,
        chain_client: object,
        now_unix: int | None = None,
        expected_epoch: int | None = None,
    ) -> dict[str, object]:
        if not RES_RE.match(resource_id or ""):
            raise ValueError("invalid resource_id")
        w = recipient_wallet.lower()
        authorize(chain_client, resource_id, w, policy_digest, now_unix)
        epoch = self.current_epoch(resource_id, w)
        if expected_epoch is not None and int(expected_epoch) != epoch:
            raise PolicyDenied("stale key epoch", "epoch")
        entry = self.keys.get(w)
        if entry is None:
            raise KeyNotRegistered(f"no encryption key for {w}")
        envelope = encrypt_envelope(insight, entry["x25519_public_key_b64"],
                                    resource_id=resource_id, recipient_wallet=w,
                                    policy_version=int(policy_version),
                                    key_epoch=epoch)
        self.items.append({"envelope": envelope, "policy_id": policy_id,
                           "created_at": time.strftime(
                               "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                           "invalidated_at": None})
        return envelope

    def for_recipient(
        self,
        wallet: str,
        resource_id: str,
        chain_client: object,
        policy_digest: str,
        *,
        now_unix: int | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, object]:
        if int(limit) > 100 or int(limit) <= 0:
            raise ValueError("limit must be 1..100")
        w = wallet.lower()
        authorize(chain_client, resource_id, w, policy_digest, now_unix)
        epoch = self.current_epoch(resource_id, w)
        rows = [it for it in self.items
                if it["envelope"]["recipient_wallet"] == w
                and it["envelope"]["resource_id"] == resource_id
                and it["invalidated_at"] is None
                and int(it["envelope"]["key_epoch"]) == epoch]
        start = int(cursor) if cursor else 0
        page = rows[start:start + int(limit)]
        nxt = str(start + int(limit)) if start + int(limit) < len(rows) else None
        return {"items": [it["envelope"] for it in page], "next_cursor": nxt}
