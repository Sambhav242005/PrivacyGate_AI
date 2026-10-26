"""Fail-closed HTTP client for the PrivacyGate v2 local validator."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Self

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .ledger import (
    LedgerError,
    _decode_b64,
    _require_int,
    _require_resource_id,
    _require_uuid,
    canonical_json,
)

OBSERVATION_KEYS = frozenset(
    {
        "chain_id",
        "genesis_hash",
        "challenge",
        "observed_at",
        "head_height",
        "head_hash",
        "resource_id",
        "owner_id",
        "recipient_id",
        "grant",
        "signature_b64",
    }
)
GRANT_KEYS = frozenset(
    {"recipient_id", "policy_digest", "expires_at", "scope", "active", "version"}
)
RECEIPT_KEYS = frozenset(
    {"transaction_id", "block_height", "block_hash", "operation", "resource_id", "version"}
)
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
ERROR_CODE_RE = re.compile(r"^[A-Z0-9_]{1,64}$")


def _verify_b64_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise LedgerError("LEDGER_PROTOCOL_ERROR", "Validator returned an invalid signature")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LedgerError(
            "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid signature"
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != value or len(decoded) != 64:
        raise LedgerError("LEDGER_PROTOCOL_ERROR", "Validator returned an invalid signature")
    return decoded


def _validate_receipt(value: Any, transaction_id: str | None = None) -> dict[str, Any]:
    if type(value) is not dict or set(value) != RECEIPT_KEYS:
        raise LedgerError("LEDGER_PROTOCOL_ERROR", "Validator returned an invalid receipt")
    try:
        _require_uuid(value["transaction_id"], "transaction_id", code="LEDGER_PROTOCOL_ERROR")
        _require_int(value["block_height"], "block_height", minimum=1, code="LEDGER_PROTOCOL_ERROR")
        _require_resource_id(value["resource_id"], code="LEDGER_PROTOCOL_ERROR")
        _require_int(value["version"], "version", minimum=1, code="LEDGER_PROTOCOL_ERROR")
    except LedgerError as exc:
        raise LedgerError("LEDGER_PROTOCOL_ERROR", "Validator returned an invalid receipt") from exc
    if transaction_id is not None and value["transaction_id"] != transaction_id:
        raise LedgerError("LEDGER_PROTOCOL_ERROR", "Receipt transaction ID does not match request")
    if not isinstance(value["operation"], str) or value["operation"] not in {
        "REGISTER_RESOURCE",
        "GRANT",
        "REVOKE",
    }:
        raise LedgerError("LEDGER_PROTOCOL_ERROR", "Validator returned an invalid receipt")
    if not isinstance(value["block_hash"], str) or HEX_RE.fullmatch(value["block_hash"]) is None:
        raise LedgerError("LEDGER_PROTOCOL_ERROR", "Validator returned an invalid receipt")
    return dict(value)


class LedgerClient:
    """HTTP client that authenticates fresh state observations and pins the head."""

    def __init__(
        self,
        url: str,
        config: dict[str, Any],
        checkpoint_path: str | os.PathLike[str] | None = None,
    ) -> None:
        if not isinstance(url, str) or not url:
            raise LedgerError("INVALID_CONFIG", "Validator URL is required")
        if type(config) is not dict:
            raise LedgerError("INVALID_CONFIG", "Public validator config must be an object")
        self.url = url.rstrip("/")
        chain_id = config.get("chain_id")
        genesis_hash = config.get("genesis_hash")
        validator_public_key_b64 = config.get("validator_public_key_b64")
        identities = config.get("identities")
        if not isinstance(chain_id, str) or not chain_id:
            raise LedgerError("INVALID_CONFIG", "Public validator config has no chain_id")
        if not isinstance(genesis_hash, str) or HEX_RE.fullmatch(genesis_hash) is None:
            raise LedgerError(
                "INVALID_CONFIG", "Public validator config has an invalid genesis_hash"
            )
        if type(identities) is not dict:
            raise LedgerError(
                "INVALID_CONFIG", "Public validator config has no provisioned identities"
            )
        if not isinstance(validator_public_key_b64, str):
            raise LedgerError(
                "INVALID_CONFIG", "Public validator config has no validator public key"
            )
        self.chain_id: str = chain_id
        self.genesis_hash: str = genesis_hash
        self.validator_public_key_b64: str = validator_public_key_b64
        for account_id, public_b64 in identities.items():
            _require_uuid(account_id, "identity account_id", code="INVALID_CONFIG")
            _decode_b64(public_b64, "identity public key", expected_length=32)
        self.identities = dict(identities)
        try:
            raw_public = _decode_b64(
                self.validator_public_key_b64,
                "validator public key",
                expected_length=32,
            )
            self._validator_public_key = Ed25519PublicKey.from_public_bytes(raw_public)
        except (LedgerError, ValueError) as exc:
            raise LedgerError(
                "INVALID_CONFIG", "Public validator config has an invalid key"
            ) from exc

        self.checkpoint_path = (
            None if checkpoint_path is None else Path(checkpoint_path).expanduser()
        )
        self._checkpoint_lock = threading.Lock()
        self._head_checkpoint: tuple[int, str] | None = None
        if self.checkpoint_path is not None:
            self._head_checkpoint = self._read_checkpoint()
        self._http = httpx.Client(timeout=5.0)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _read_checkpoint(self) -> tuple[int, str] | None:
        path = self.checkpoint_path
        if path is None or not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LedgerError(
                "CHECKPOINT_INVALID", "Ledger head checkpoint could not be read"
            ) from exc
        expected = {"schema_version", "chain_id", "genesis_hash", "head_height", "head_hash"}
        if type(value) is not dict or set(value) != expected:
            raise LedgerError("CHECKPOINT_INVALID", "Ledger head checkpoint has invalid fields")
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 2
            or value["chain_id"] != self.chain_id
            or value["genesis_hash"] != self.genesis_hash
        ):
            raise LedgerError(
                "CHECKPOINT_CONFIG_MISMATCH", "Ledger head checkpoint belongs to another chain"
            )
        try:
            height = _require_int(
                value["head_height"], "head_height", minimum=0, code="CHECKPOINT_INVALID"
            )
        except LedgerError as exc:
            raise LedgerError(
                "CHECKPOINT_INVALID", "Ledger head checkpoint has invalid height"
            ) from exc
        head_hash = value["head_hash"]
        if not isinstance(head_hash, str) or HEX_RE.fullmatch(head_hash) is None:
            raise LedgerError("CHECKPOINT_INVALID", "Ledger head checkpoint has invalid hash")
        if height == 0 and head_hash != self.genesis_hash:
            raise LedgerError("CHECKPOINT_INVALID", "Genesis checkpoint hash is invalid")
        return (height, head_hash)

    def _write_checkpoint(self, height: int, head_hash: str) -> None:
        path = self.checkpoint_path
        if path is None:
            self._head_checkpoint = (height, head_hash)
            return
        value = {
            "schema_version": 2,
            "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash,
            "head_height": height,
            "head_hash": head_hash,
        }
        encoded = canonical_json(value)
        temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise LedgerError(
                "CHECKPOINT_WRITE_FAILED", "Ledger head checkpoint could not be persisted"
            ) from exc
        self._head_checkpoint = (height, head_hash)

    def _accept_head(self, height: int, head_hash: str) -> None:
        with self._checkpoint_lock:
            known = self._head_checkpoint
            if known is not None:
                known_height, known_hash = known
                if height < known_height:
                    raise LedgerError(
                        "LEDGER_ROLLBACK", "Validator head is below the persisted checkpoint"
                    )
                if height == known_height and head_hash != known_hash:
                    raise LedgerError(
                        "LEDGER_HEAD_CONFLICT",
                        "Validator head conflicts with the persisted checkpoint",
                    )
            self._write_checkpoint(height, head_hash)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        allow_missing_receipt: bool = False,
    ) -> Any:
        try:
            response = self._http.request(
                method,
                f"{self.url}{path}",
                json=json_body,
            )
        except httpx.HTTPError as exc:
            raise LedgerError("LEDGER_UNAVAILABLE", "Validator is unavailable") from exc
        try:
            value = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise LedgerError("LEDGER_PROTOCOL_ERROR", "Validator returned invalid JSON") from exc
        if (
            allow_missing_receipt
            and response.status_code == 404
            and type(value) is dict
            and type(value.get("error")) is dict
            and value["error"].get("code") == "RECEIPT_NOT_FOUND"
        ):
            return None
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            error = value.get("error") if type(value) is dict else None
            code = error.get("code") if type(error) is dict else None
            message = error.get("message") if type(error) is dict else None
            if not isinstance(code, str) or ERROR_CODE_RE.fullmatch(code) is None:
                code = (
                    "LEDGER_UNAVAILABLE"
                    if response.status_code >= 500
                    else "LEDGER_REQUEST_REJECTED"
                )
            if not isinstance(message, str) or len(message) > 240:
                message = (
                    "Validator rejected the request"
                    if response.status_code < 500
                    else "Validator is unavailable"
                )
            raise LedgerError(code, message) from exc
        return value

    def submit(self, transaction: dict[str, Any]) -> dict[str, Any]:
        value = self._request("POST", "/transactions", json_body=transaction)
        transaction_id = transaction.get("transaction_id") if type(transaction) is dict else None
        if not isinstance(transaction_id, str):
            raise LedgerError("INVALID_TRANSACTION", "Transaction ID is required")
        return _validate_receipt(value, transaction_id)

    def receipt(self, transaction_id: str) -> dict[str, Any] | None:
        _require_uuid(transaction_id, "transaction_id", code="INVALID_TRANSACTION")
        value = self._request(
            "GET",
            f"/receipts/{transaction_id}",
            allow_missing_receipt=True,
        )
        if value is None:
            return None
        return _validate_receipt(value, transaction_id)

    def next_nonce(self, signer_id: str) -> int:
        _require_uuid(signer_id, "signer_id", code="INVALID_SIGNER")
        if signer_id not in self.identities:
            raise LedgerError("IDENTITY_NOT_PROVISIONED", "Signer is not provisioned")
        value = self._request("GET", f"/nonces/{signer_id}")
        if type(value) is not dict or set(value) != {"signer_id", "next_nonce"}:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid nonce response"
            )
        if value["signer_id"] != signer_id:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned a nonce for another signer"
            )
        try:
            return _require_int(
                value["next_nonce"], "next_nonce", minimum=1, code="LEDGER_PROTOCOL_ERROR"
            )
        except LedgerError as exc:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid nonce response"
            ) from exc

    def state(self, resource_id: str, recipient_id: str) -> dict[str, Any]:
        _require_resource_id(resource_id, code="INVALID_STATE_REQUEST")
        _require_uuid(recipient_id, "recipient_id", code="INVALID_STATE_REQUEST")
        if recipient_id not in self.identities:
            raise LedgerError(
                "RECIPIENT_NOT_PROVISIONED", "Observation recipient is not provisioned"
            )
        challenge = secrets.token_urlsafe(32)
        value = self._request(
            "POST",
            "/state",
            json_body={
                "resource_id": resource_id,
                "recipient_id": recipient_id,
                "challenge": challenge,
            },
        )
        if type(value) is not dict or set(value) != OBSERVATION_KEYS:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid state observation"
            )
        if (
            value["chain_id"] != self.chain_id
            or value["genesis_hash"] != self.genesis_hash
            or value["challenge"] != challenge
            or value["resource_id"] != resource_id
            or value["recipient_id"] != recipient_id
        ):
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "State observation context does not match request"
            )
        owner_id = value["owner_id"]
        if owner_id is None:
            if value["grant"] is not None:
                raise LedgerError("LEDGER_PROTOCOL_ERROR", "Absent resource cannot contain a grant")
        else:
            try:
                _require_uuid(owner_id, "owner_id", code="LEDGER_PROTOCOL_ERROR")
            except LedgerError as exc:
                raise LedgerError(
                    "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid state observation"
                ) from exc
            if owner_id == recipient_id:
                raise LedgerError(
                    "LEDGER_PROTOCOL_ERROR", "Observation recipient cannot own the resource"
                )
        try:
            observed_at = _require_int(
                value["observed_at"], "observed_at", minimum=1, code="LEDGER_PROTOCOL_ERROR"
            )
            head_height = _require_int(
                value["head_height"], "head_height", minimum=0, code="LEDGER_PROTOCOL_ERROR"
            )
        except LedgerError as exc:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid state observation"
            ) from exc
        head_hash = value["head_hash"]
        if not isinstance(head_hash, str) or HEX_RE.fullmatch(head_hash) is None:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid state observation"
            )
        if head_height == 0 and head_hash != self.genesis_hash:
            raise LedgerError("LEDGER_PROTOCOL_ERROR", "Genesis observation hash is invalid")
        if abs(observed_at - int(time.time())) > 5:
            raise LedgerError(
                "STALE_OBSERVATION", "State observation is outside the accepted time window"
            )
        self._validate_grant(value["grant"], recipient_id, observed_at)

        signature = _verify_b64_signature(value["signature_b64"])
        body = {key: item for key, item in value.items() if key != "signature_b64"}
        try:
            self._validator_public_key.verify(signature, canonical_json(body))
        except InvalidSignature as exc:
            raise LedgerError(
                "INVALID_OBSERVATION_SIGNATURE", "State observation signature is invalid"
            ) from exc

        self._accept_head(head_height, head_hash)
        return dict(value)

    @staticmethod
    def _validate_grant(grant: Any, recipient_id: str, observed_at: int) -> None:
        if grant is None:
            return
        if type(grant) is not dict or set(grant) != GRANT_KEYS:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid grant observation"
            )
        if grant["recipient_id"] != recipient_id:
            raise LedgerError("LEDGER_PROTOCOL_ERROR", "Grant recipient does not match observation")
        if (
            not isinstance(grant["policy_digest"], str)
            or HEX_RE.fullmatch(grant["policy_digest"]) is None
        ):
            raise LedgerError("LEDGER_PROTOCOL_ERROR", "Validator returned an invalid grant digest")
        if grant["scope"] != "READ_INSIGHT" or type(grant["active"]) is not bool:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned an invalid grant scope or status"
            )
        try:
            expires_at = _require_int(
                grant["expires_at"], "expires_at", minimum=1, code="LEDGER_PROTOCOL_ERROR"
            )
            _require_int(grant["version"], "version", minimum=1, code="LEDGER_PROTOCOL_ERROR")
        except LedgerError as exc:
            raise LedgerError(
                "LEDGER_PROTOCOL_ERROR", "Validator returned invalid grant fields"
            ) from exc
        if grant["active"] and expires_at <= observed_at:
            raise LedgerError("LEDGER_PROTOCOL_ERROR", "Expired grant was reported active")
