"""PG-032 policy-checked dispatch + encrypted queue (ciphertext only).

Flow per delivery: fresh chain authorize() -> key lookup -> envelope
encrypt (ephemeral X25519 + HKDF-SHA256 + AES-256-GCM, mature
`cryptography` lib) -> append ciphertext record. Revoked/expired grants,
digest mismatch, missing keys, and stale key epochs all block BEFORE any
crypto. The queue stores ciphertext + metadata only; plaintext InsightV1
bytes exist transiently inside dispatch() and never persist.
"""
from __future__ import annotations

import json
import re
import time
import uuid

from privacygate.chain.permissions import PolicyDenied, authorize
from privacygate.domain.schemas import InsightV1, b64decode_exact
from privacygate.security.envelopes import decrypt_insight, encrypt_insight

WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
RES_RE = re.compile(r"^0x[0-9a-f]{64}$")


class KeyNotRegistered(Exception):
    pass


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
    """Delegate to security/envelopes.py (single DESIGN-7 wire format)."""
    return encrypt_insight(
        insight.model_dump(mode="json"), recipient_pub_b64,
        resource_id=resource_id, recipient_wallet=recipient_wallet,
        policy_version=int(policy_version), key_epoch=int(key_epoch),
        delivery_id=delivery_id)


def decrypt_envelope(envelope: dict, recipient_priv_b64: str) -> InsightV1:
    """Client-side reference decryption (tests/subscriber app)."""
    return InsightV1.model_validate(decrypt_insight(envelope, recipient_priv_b64))


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
        b64decode_exact(pub_b64, 32, "x25519 key")
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
