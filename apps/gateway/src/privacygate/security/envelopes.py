"""PG-031 per-recipient envelope crypto (X25519 + HKDF-SHA256 + AES-GCM).

Envelope shape follows packages/shared/json-schema/envelope-v1.json (golden).
Plaintext is canonical InsightV1 JSON (exactly 5 fields). AAD is the canonical
JSON bytes of the 7-field header also carried as ``aad_b64``:

  schema_version, delivery_id, event_id, resource_id,
  recipient_wallet, policy_version, key_epoch

HKDF-SHA256 info is domain-separated per DESIGN.md section 7:

  info = b"privacygate-envelope-v1|" + canonical_json({
      "event_id": ..., "key_epoch": ..., "policy_version": ...,
      "recipient_wallet": ..., "resource_id": ...,
  })

(canonical JSON: sorted keys, separators (",", ":")).

with ``salt=None`` (a HashLen-length zero string per RFC 5869). Browser
decryptors must use identical params: salt = 32 zero bytes for SHA-256
(WebCrypto has no ``None``; an empty salt derives a different key).
NOTE: the orchestration brief described AAD as
``sha256(canonical insight)||policy_digest||recipient||epoch``; the normative
golden fixture + DATA_MODEL carry a 7-field JSON AAD with no policy_digest on
the wire (recipient could not reconstruct an HKDF/policy check needing it at
decrypt time), so this module binds policy_digest-free context per DESIGN 7.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import uuid
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SCHEMA_VERSION = 1
WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
RES_RE = re.compile(r"^0x[0-9a-f]{64}$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
INSIGHT_FIELDS = frozenset(
    ("event_id", "event_type", "severity", "observed_at", "model_version")
)
AAD_FIELDS = (
    "schema_version",
    "delivery_id",
    "event_id",
    "resource_id",
    "recipient_wallet",
    "policy_version",
    "key_epoch",
)
_HKDF_DOMAIN = b"privacygate-envelope-v1|"


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _b64decode_exact(value: str, nbytes: int, name: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid {name}: {e}") from e
    if len(raw) != nbytes:
        raise ValueError(f"invalid {name}: want {nbytes} bytes, got {len(raw)}")
    return raw


def _normalize_wallet(wallet: str) -> str:
    if not isinstance(wallet, str) or not WALLET_RE.match(wallet):
        raise ValueError("invalid wallet address")
    return wallet.lower()


def _validate_insight(insight: dict[str, Any]) -> dict[str, Any]:
    """Strict InsightV1 check without importing domain layer (crypto-only)."""
    if not isinstance(insight, dict) or set(insight) != set(INSIGHT_FIELDS):
        raise ValueError("insight must hold exactly the 5 InsightV1 fields")
    if insight.get("event_type") != "MACHINE_ANOMALY":
        raise ValueError("unsupported event_type")
    if insight.get("severity") not in ("LOW", "MEDIUM", "HIGH"):
        raise ValueError("unsupported severity")
    for key in ("event_id", "observed_at", "model_version"):
        if not isinstance(insight.get(key), str) or not insight[key]:
            raise ValueError(f"invalid {key}")
    if not UUID_RE.match(str(insight["event_id"])):
        raise ValueError("invalid event_id")
    return insight


def build_aad(
    *,
    delivery_id: str,
    event_id: str,
    resource_id: str,
    recipient_wallet: str,
    policy_version: int,
    key_epoch: int,
) -> bytes:
    if not UUID_RE.match(delivery_id):
        raise ValueError("invalid delivery_id")
    if not UUID_RE.match(str(event_id)):
        raise ValueError("invalid event_id")
    if not RES_RE.match(resource_id):
        raise ValueError("invalid resource_id")
    recipient_wallet = _normalize_wallet(recipient_wallet)
    if not isinstance(policy_version, int) or policy_version < 1:
        raise ValueError("invalid policy_version")
    if not isinstance(key_epoch, int) or key_epoch < 0:
        raise ValueError("invalid key_epoch")
    return canonical_json(
        {
            "schema_version": SCHEMA_VERSION,
            "delivery_id": delivery_id,
            "event_id": str(event_id),
            "resource_id": resource_id,
            "recipient_wallet": recipient_wallet,
            "policy_version": policy_version,
            "key_epoch": key_epoch,
        }
    )


def _hkdf_info(
    *,
    recipient_wallet: str,
    resource_id: str,
    event_id: str,
    policy_version: int,
    key_epoch: int,
) -> bytes:
    return (
        _HKDF_DOMAIN
        + canonical_json(
            {
                "event_id": str(event_id),
                "key_epoch": key_epoch,
                "policy_version": policy_version,
                "recipient_wallet": recipient_wallet.lower(),
                "resource_id": resource_id,
            }
        )
    )


def _derive_key(shared_secret: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(shared_secret)


def generate_recipient_keypair() -> tuple[str, str]:
    """Return (private_b64, public_b64) X25519 pair. Test/demo helper."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return (
        base64.b64encode(priv.private_bytes_raw()).decode(),
        base64.b64encode(pub.public_bytes_raw()).decode(),
    )


def public_b64_from_private(private_b64: str) -> str:
    raw = _b64decode_exact(private_b64, 32, "private key")
    pub = X25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.b64encode(pub.public_bytes_raw()).decode()


def encrypt_insight(
    insight: dict[str, Any],
    recipient_public_key_b64: str,
    *,
    resource_id: str,
    recipient_wallet: str,
    policy_version: int,
    key_epoch: int,
    delivery_id: str | None = None,
) -> dict[str, Any]:
    _validate_insight(insight)
    peer_raw = _b64decode_exact(
        recipient_public_key_b64, 32, "recipient public key"
    )
    if not RES_RE.match(resource_id):
        raise ValueError("invalid resource_id")
    recipient_wallet = _normalize_wallet(recipient_wallet)
    if not isinstance(policy_version, int) or policy_version < 1:
        raise ValueError("invalid policy_version")
    if not isinstance(key_epoch, int) or key_epoch < 0:
        raise ValueError("invalid key_epoch")
    delivery_id = delivery_id or str(uuid.uuid4())
    if not UUID_RE.match(delivery_id):
        raise ValueError("invalid delivery_id")

    event_id = str(insight["event_id"])
    aad = build_aad(
        delivery_id=delivery_id,
        event_id=event_id,
        resource_id=resource_id,
        recipient_wallet=recipient_wallet,
        policy_version=policy_version,
        key_epoch=key_epoch,
    )
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key()
    peer = X25519PublicKey.from_public_bytes(peer_raw)
    shared = ephemeral.exchange(peer)
    key = _derive_key(
        shared,
        _hkdf_info(
            recipient_wallet=recipient_wallet,
            resource_id=resource_id,
            event_id=event_id,
            policy_version=policy_version,
            key_epoch=key_epoch,
        ),
    )
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, canonical_json(insight), aad)
    return {
        "delivery_id": delivery_id,
        "schema_version": SCHEMA_VERSION,
        "resource_id": resource_id,
        "recipient_wallet": recipient_wallet,
        "policy_version": policy_version,
        "key_epoch": key_epoch,
        "ephemeral_public_key_b64": base64.b64encode(
            ephemeral_pub.public_bytes_raw()
        ).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "aad_b64": base64.b64encode(aad).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
    }


def decrypt_insight(
    envelope: dict[str, Any], recipient_private_key_b64: str
) -> dict[str, Any]:
    """Decrypt + verify envelope. Raises ValueError on any tamper/mismatch."""
    try:
        priv_raw = _b64decode_exact(
            recipient_private_key_b64, 32, "private key"
        )
        eph_raw = _b64decode_exact(
            str(envelope["ephemeral_public_key_b64"]), 32, "ephemeral key"
        )
        nonce = _b64decode_exact(str(envelope["nonce_b64"]), 12, "nonce")
        try:
            aad_wire = base64.b64decode(str(envelope["aad_b64"]), validate=True)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"invalid aad: {e}") from e
        try:
            ciphertext = base64.b64decode(
                str(envelope["ciphertext_b64"]), validate=True
            )
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"invalid ciphertext: {e}") from e
        if not ciphertext:
            raise ValueError("empty ciphertext")

        aad_obj = json.loads(aad_wire.decode("utf-8"))
        if not isinstance(aad_obj, dict) or set(aad_obj) != set(AAD_FIELDS):
            raise ValueError("AAD fields mismatch")
        # AAD must mirror envelope header exactly (binds delivery context).
        for field in (
            "schema_version",
            "delivery_id",
            "resource_id",
            "recipient_wallet",
            "policy_version",
            "key_epoch",
        ):
            if aad_obj[field] != envelope[field]:
                raise ValueError(f"AAD {field} mismatch")
        if aad_obj["schema_version"] != SCHEMA_VERSION:
            raise ValueError("unsupported schema_version")
        expected_aad = build_aad(
            delivery_id=str(aad_obj["delivery_id"]),
            event_id=str(aad_obj["event_id"]),
            resource_id=str(aad_obj["resource_id"]),
            recipient_wallet=str(aad_obj["recipient_wallet"]),
            policy_version=int(aad_obj["policy_version"]),
            key_epoch=int(aad_obj["key_epoch"]),
        )
        if expected_aad != aad_wire:
            raise ValueError("AAD encoding mismatch")

        info = _hkdf_info(
            recipient_wallet=str(aad_obj["recipient_wallet"]),
            resource_id=str(aad_obj["resource_id"]),
            event_id=str(aad_obj["event_id"]),
            policy_version=int(aad_obj["policy_version"]),
            key_epoch=int(aad_obj["key_epoch"]),
        )
        shared = X25519PrivateKey.from_private_bytes(
            priv_raw
        ).exchange(X25519PublicKey.from_public_bytes(eph_raw))
        key = _derive_key(shared, info)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad_wire)
        insight = json.loads(plaintext.decode("utf-8"))
        return _validate_insight(insight)
    except (InvalidTag, ValueError) as e:
        raise ValueError(f"envelope decrypt failed: {e}") from e
