"""SQLite-backed, single-validator authorization ledger for PrivacyGate v2.

The ledger stores only the signed authorization transactions described in
``docs/V2.md``.  It is a local demonstration chain, not a consensus protocol.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

SCHEMA_VERSION = 2
DEFAULT_CHAIN_ID = "privacygate-local-v2"
TRANSACTION_KEYS = frozenset(
    {
        "schema_version",
        "chain_id",
        "transaction_id",
        "signer_id",
        "nonce",
        "issued_at",
        "operation",
        "payload",
        "signature_b64",
    }
)
BLOCK_KEYS = frozenset(
    {
        "height",
        "previous_hash",
        "committed_at",
        "transaction",
        "block_hash",
        "validator_signature_b64",
    }
)
RESOURCE_RE = re.compile(r"^0x[0-9a-f]{64}$")
HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
OPERATIONS = frozenset({"REGISTER_RESOURCE", "GRANT", "REVOKE"})
MAX_TX_AGE_SECONDS = 30


class LedgerError(Exception):
    """Stable, non-sensitive error returned by the ledger and its HTTP API."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def canonical_json(value: Any) -> bytes:
    """Return the v2 canonical JSON byte representation."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise LedgerError("INVALID_JSON", "Value is not canonical JSON data") from exc


def _sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _require_uuid(value: Any, field: str, code: str = "INVALID_TRANSACTION") -> str:
    if not isinstance(value, str):
        raise LedgerError(code, f"{field} must be a canonical UUID")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise LedgerError(code, f"{field} must be a canonical UUID") from exc
    if canonical != value:
        raise LedgerError(code, f"{field} must be a canonical UUID")
    return value


def _require_resource_id(value: Any, code: str = "INVALID_TRANSACTION") -> str:
    if not isinstance(value, str) or RESOURCE_RE.fullmatch(value) is None:
        raise LedgerError(code, "resource_id must be lowercase 0x followed by 64 hex characters")
    return value


def _require_int(
    value: Any, field: str, minimum: int = 0, code: str = "INVALID_TRANSACTION"
) -> int:
    if type(value) is not int or value < minimum:
        raise LedgerError(code, f"{field} must be an integer greater than or equal to {minimum}")
    return value


def _decode_b64(value: Any, field: str, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise LedgerError("INVALID_CONFIG", f"{field} must be standard base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LedgerError("INVALID_CONFIG", f"{field} must be standard base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise LedgerError("INVALID_CONFIG", f"{field} must use canonical standard base64")
    if expected_length is not None and len(decoded) != expected_length:
        raise LedgerError("INVALID_CONFIG", f"{field} has an invalid key length")
    return decoded


def _decode_signature(value: Any, field: str = "signature_b64") -> bytes:
    if not isinstance(value, str):
        raise LedgerError("INVALID_TRANSACTION", f"{field} must be standard base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LedgerError("INVALID_TRANSACTION", f"{field} must be standard base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value or len(decoded) != 64:
        raise LedgerError("INVALID_TRANSACTION", f"{field} must encode a 64-byte signature")
    return decoded


def _private_key_from_b64(value: str) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(
            _decode_b64(value, "private key", expected_length=32)
        )
    except ValueError as exc:
        raise LedgerError("INVALID_CONFIG", "Invalid Ed25519 private key") from exc


def _public_key_from_b64(value: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(
            _decode_b64(value, "public key", expected_length=32)
        )
    except ValueError as exc:
        raise LedgerError("INVALID_CONFIG", "Invalid Ed25519 public key") from exc


def _validate_payload(operation: Any, payload: Any) -> dict[str, Any]:
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise LedgerError("INVALID_OPERATION", "Unsupported ledger operation")
    if type(payload) is not dict:
        raise LedgerError("INVALID_PAYLOAD", "payload must be an object")

    if operation == "REGISTER_RESOURCE":
        if set(payload) != {"resource_id"}:
            raise LedgerError("INVALID_PAYLOAD", "REGISTER_RESOURCE payload has invalid fields")
        _require_resource_id(payload["resource_id"])
    elif operation == "GRANT":
        required = {"resource_id", "recipient_id", "policy_digest", "expires_at", "scope"}
        if set(payload) != required:
            raise LedgerError("INVALID_PAYLOAD", "GRANT payload has invalid fields")
        _require_resource_id(payload["resource_id"])
        _require_uuid(payload["recipient_id"], "recipient_id")
        if (
            not isinstance(payload["policy_digest"], str)
            or HEX_DIGEST_RE.fullmatch(payload["policy_digest"]) is None
        ):
            raise LedgerError(
                "INVALID_PAYLOAD", "policy_digest must be a lowercase SHA256 hex digest"
            )
        _require_int(payload["expires_at"], "expires_at", minimum=1)
        if payload["scope"] != "READ_INSIGHT":
            raise LedgerError("INVALID_SCOPE", "Only READ_INSIGHT is supported")
    else:
        if set(payload) != {"resource_id", "recipient_id"}:
            raise LedgerError("INVALID_PAYLOAD", "REVOKE payload has invalid fields")
        _require_resource_id(payload["resource_id"])
        _require_uuid(payload["recipient_id"], "recipient_id")

    # Return a fresh JSON-compatible object so callers cannot mutate the signed payload.
    return dict(payload)


def _validate_transaction_shape(transaction: Any) -> dict[str, Any]:
    if type(transaction) is not dict or set(transaction) != TRANSACTION_KEYS:
        raise LedgerError("INVALID_TRANSACTION", "Transaction fields do not match schema v2")
    if (
        type(transaction["schema_version"]) is not int
        or transaction["schema_version"] != SCHEMA_VERSION
    ):
        raise LedgerError("INVALID_TRANSACTION", "Unsupported transaction schema version")
    chain_id = transaction["chain_id"]
    if not isinstance(chain_id, str) or not chain_id or len(chain_id) > 128:
        raise LedgerError("INVALID_TRANSACTION", "chain_id must be a non-empty string")
    _require_uuid(transaction["transaction_id"], "transaction_id")
    _require_uuid(transaction["signer_id"], "signer_id")
    _require_int(transaction["nonce"], "nonce", minimum=1)
    _require_int(transaction["issued_at"], "issued_at", minimum=1)
    normalized_payload = _validate_payload(transaction["operation"], transaction["payload"])
    _decode_signature(transaction["signature_b64"])
    # Round-trip JSON values here to reject nested objects, unsupported values, and NaN.
    try:
        canonical_json(transaction)
    except LedgerError as exc:
        raise LedgerError("INVALID_TRANSACTION", "Transaction is not valid JSON data") from exc
    return {**transaction, "payload": normalized_payload}


def _unsigned_transaction(transaction: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in transaction.items() if key != "signature_b64"}


def sign_transaction(
    private_b64: str,
    chain_id: str,
    signer_id: str,
    nonce: int,
    operation: str,
    payload: dict[str, Any],
    transaction_id: str | None = None,
    issued_at: int | None = None,
) -> dict[str, Any]:
    """Sign an exact v2 transaction using a raw 32-byte Ed25519 private key."""

    if not isinstance(chain_id, str) or not chain_id or len(chain_id) > 128:
        raise LedgerError("INVALID_TRANSACTION", "chain_id must be a non-empty string")
    _require_uuid(signer_id, "signer_id")
    nonce = _require_int(nonce, "nonce", minimum=1)
    transaction_id = str(uuid.uuid4()) if transaction_id is None else transaction_id
    issued_at = int(time.time()) if issued_at is None else issued_at
    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "chain_id": chain_id,
        "transaction_id": transaction_id,
        "signer_id": signer_id,
        "nonce": nonce,
        "issued_at": issued_at,
        "operation": operation,
        "payload": _validate_payload(operation, payload),
    }
    _require_uuid(transaction_id, "transaction_id")
    _require_int(issued_at, "issued_at", minimum=1)
    signature = _private_key_from_b64(private_b64).sign(canonical_json(unsigned))
    return {**unsigned, "signature_b64": base64.b64encode(signature).decode("ascii")}


class Ledger:
    """Append-only SQLite authorization ledger validated on every startup."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        validator_private_key_b64: str,
        identities: dict[str, str],
        chain_id: str = DEFAULT_CHAIN_ID,
    ) -> None:
        if not isinstance(chain_id, str) or not chain_id or len(chain_id) > 128:
            raise LedgerError("INVALID_CONFIG", "chain_id must be a non-empty string")
        if type(identities) is not dict or not identities:
            raise LedgerError("INVALID_CONFIG", "At least one provisioned identity is required")

        normalized_identities: dict[str, str] = {}
        self._identity_keys: dict[str, Ed25519PublicKey] = {}
        for account_id, public_b64 in identities.items():
            _require_uuid(account_id, "identity account_id", code="INVALID_CONFIG")
            if account_id in normalized_identities:
                raise LedgerError("INVALID_CONFIG", "Duplicate provisioned identity")
            if not isinstance(public_b64, str):
                raise LedgerError("INVALID_CONFIG", "Identity public keys must be base64 strings")
            normalized_identities[account_id] = public_b64
            self._identity_keys[account_id] = _public_key_from_b64(public_b64)
        self._identities = dict(sorted(normalized_identities.items()))

        self._validator_private_key = _private_key_from_b64(validator_private_key_b64)
        validator_public_key = self._validator_private_key.public_key()
        public_raw = validator_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._validator_public_key_b64 = base64.b64encode(public_raw).decode("ascii")
        self._validator_public_key = validator_public_key
        self.chain_id = chain_id

        if str(db_path) == ":memory:":
            self.db_path = ":memory:"
            self._connect_target = f"file:privacygate-{uuid.uuid4()}?mode=memory&cache=shared"
            self._use_uri = True
            self._database_existed_before_open = False
            self._keeper: sqlite3.Connection | None = None
            self._keeper = self._connect()
        else:
            resolved_path = Path(db_path).expanduser().resolve()
            self._database_existed_before_open = resolved_path.exists()
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(resolved_path)
            self._connect_target = self.db_path
            self._use_uri = False
            self._keeper = None

        self._genesis_hash = _sha256_hex(
            {
                "schema_version": SCHEMA_VERSION,
                "chain_id": self.chain_id,
                "validator_public_key_b64": self._validator_public_key_b64,
                "identities": self._identities,
            }
        )
        self._config_record = canonical_json(self.config).decode("utf-8")
        self._initialize_database()
        self.verify()

    @property
    def config(self) -> dict[str, Any]:
        """Return a copy of the public, immutable chain configuration."""

        return {
            "genesis_hash": self._genesis_hash,
            "chain_id": self.chain_id,
            "validator_public_key_b64": self._validator_public_key_b64,
            "identities": dict(self._identities),
        }

    def public_config(self) -> dict[str, Any]:
        return self.config

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._connect_target,
            timeout=30,
            isolation_level=None,
            uri=self._use_uri,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _initialize_database(self) -> None:
        try:
            with self._connection() as conn:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                table_names = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                if version == 0:
                    if table_names:
                        raise LedgerError(
                            "LEDGER_CORRUPT", "Unversioned ledger database is not empty"
                        )
                    if self._database_existed_before_open:
                        raise LedgerError(
                            "LEDGER_CORRUPT", "Existing empty ledger database cannot be reset"
                        )
                    self._create_schema(conn)
                elif version != SCHEMA_VERSION:
                    raise LedgerError(
                        "LEDGER_SCHEMA_UNSUPPORTED", "Ledger database schema version is unsupported"
                    )
                else:
                    self._check_pinned_config(conn)
        except LedgerError:
            raise
        except sqlite3.Error as exc:
            raise LedgerError(
                "LEDGER_CORRUPT", "Ledger database could not be opened safely"
            ) from exc

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("CREATE TABLE ledger_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE blocks ("
                "height INTEGER PRIMARY KEY, previous_hash TEXT NOT NULL, committed_at INTEGER NOT NULL, "
                "block_hash TEXT NOT NULL UNIQUE, transaction_id TEXT NOT NULL UNIQUE, block_json TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE transactions ("
                "transaction_id TEXT PRIMARY KEY, transaction_json TEXT NOT NULL, block_height INTEGER NOT NULL UNIQUE, "
                "block_hash TEXT NOT NULL, operation TEXT NOT NULL, resource_id TEXT NOT NULL, version INTEGER NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE signer_nonces (signer_id TEXT PRIMARY KEY, nonce INTEGER NOT NULL CHECK (nonce > 0))"
            )
            conn.execute(
                "CREATE TABLE resources (resource_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, version INTEGER NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE grants ("
                "resource_id TEXT NOT NULL, recipient_id TEXT NOT NULL, policy_digest TEXT NOT NULL, "
                "expires_at INTEGER NOT NULL, scope TEXT NOT NULL, active INTEGER NOT NULL CHECK (active IN (0, 1)), "
                "version INTEGER NOT NULL CHECK (version > 0), PRIMARY KEY (resource_id, recipient_id))"
            )
            initial_meta = {
                "chain_config": self._config_record,
                "genesis_hash": self._genesis_hash,
                "head_height": "0",
                "head_hash": self._genesis_hash,
                "clock_watermark": "0",
            }
            conn.executemany(
                "INSERT INTO ledger_meta (key, value) VALUES (?, ?)",
                sorted(initial_meta.items()),
            )
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _check_pinned_config(self, conn: sqlite3.Connection) -> None:
        rows = dict(conn.execute("SELECT key, value FROM ledger_meta").fetchall())
        if "chain_config" not in rows or "genesis_hash" not in rows:
            raise LedgerError("LEDGER_CORRUPT", "Pinned ledger configuration is missing")
        if (
            rows.get("chain_config") != self._config_record
            or rows.get("genesis_hash") != self._genesis_hash
        ):
            raise LedgerError("CHAIN_CONFIG_MISMATCH", "Provisioned chain identities are immutable")

    def _before_commit(self) -> None:
        """Internal crash-injection seam; called before a transaction commits."""

    def _after_commit(self) -> None:
        """Internal crash-injection seam; called after durable commit succeeds."""

    def _assert_clock(self, conn: sqlite3.Connection, now: int) -> int:
        row = conn.execute("SELECT value FROM ledger_meta WHERE key = 'clock_watermark'").fetchone()
        if row is None:
            raise LedgerError("LEDGER_CORRUPT", "Ledger clock state is missing")
        try:
            watermark = int(row[0])
        except (TypeError, ValueError) as exc:
            raise LedgerError("LEDGER_CORRUPT", "Ledger clock state is invalid") from exc
        if now < watermark:
            raise LedgerError("CLOCK_REGRESSION", "Ledger clock moved behind its confirmed time")
        return watermark

    def _verify_transaction_signature(self, transaction: dict[str, Any]) -> None:
        signer_id = transaction["signer_id"]
        public_key = self._identity_keys.get(signer_id)
        if public_key is None:
            raise LedgerError("IDENTITY_NOT_PROVISIONED", "Transaction signer is not provisioned")
        signature = _decode_signature(transaction["signature_b64"])
        try:
            public_key.verify(signature, canonical_json(_unsigned_transaction(transaction)))
        except InvalidSignature as exc:
            raise LedgerError("INVALID_SIGNATURE", "Transaction signature is invalid") from exc

    def _validate_for_chain(
        self, transaction: Any, now: int, *, check_freshness: bool
    ) -> dict[str, Any]:
        normalized = _validate_transaction_shape(transaction)
        if normalized["chain_id"] != self.chain_id:
            raise LedgerError("CHAIN_MISMATCH", "Transaction targets a different chain")
        self._verify_transaction_signature(normalized)
        if check_freshness and abs(normalized["issued_at"] - now) > MAX_TX_AGE_SECONDS:
            raise LedgerError(
                "TRANSACTION_EXPIRED", "New transaction is outside the accepted time window"
            )
        return normalized

    def _apply_new_transaction(
        self, conn: sqlite3.Connection, transaction: dict[str, Any], now: int
    ) -> int:
        operation = transaction["operation"]
        payload = transaction["payload"]
        signer_id = transaction["signer_id"]
        resource_id = payload["resource_id"]
        resource = conn.execute(
            "SELECT owner_id, version FROM resources WHERE resource_id = ?", (resource_id,)
        ).fetchone()

        if operation == "REGISTER_RESOURCE":
            if resource is not None:
                raise LedgerError("RESOURCE_ALREADY_REGISTERED", "Resource ownership is immutable")
            conn.execute(
                "INSERT INTO resources (resource_id, owner_id, version) VALUES (?, ?, 1)",
                (resource_id, signer_id),
            )
            return 1

        if resource is None:
            raise LedgerError("RESOURCE_NOT_FOUND", "Resource is not registered")
        if resource["owner_id"] != signer_id:
            raise LedgerError(
                "OWNER_REQUIRED", "Only the immutable resource owner may change grants"
            )

        recipient_id = payload["recipient_id"]
        if recipient_id == resource["owner_id"]:
            raise LedgerError("OWNER_CANNOT_BE_READER", "Resource owner cannot be a reader")
        if recipient_id not in self._identity_keys:
            raise LedgerError("RECIPIENT_NOT_PROVISIONED", "Grant recipient is not provisioned")

        old_grant = conn.execute(
            "SELECT policy_digest, expires_at, scope, active, version FROM grants "
            "WHERE resource_id = ? AND recipient_id = ?",
            (resource_id, recipient_id),
        ).fetchone()
        if operation == "GRANT":
            expires_at = payload["expires_at"]
            if expires_at <= now:
                raise LedgerError("GRANT_EXPIRED", "Grant expiry must be in the future")
            version = 1 if old_grant is None else old_grant["version"] + 1
            conn.execute(
                "INSERT INTO grants (resource_id, recipient_id, policy_digest, expires_at, scope, active, version) "
                "VALUES (?, ?, ?, ?, ?, 1, ?) ON CONFLICT(resource_id, recipient_id) DO UPDATE SET "
                "policy_digest = excluded.policy_digest, expires_at = excluded.expires_at, "
                "scope = excluded.scope, active = 1, version = excluded.version",
                (
                    resource_id,
                    recipient_id,
                    payload["policy_digest"],
                    expires_at,
                    payload["scope"],
                    version,
                ),
            )
            return version

        if old_grant is None:
            raise LedgerError("GRANT_NOT_FOUND", "No grant exists for this reader")
        if old_grant["active"] != 1:
            raise LedgerError("GRANT_NOT_ACTIVE", "Grant is already revoked")
        version = old_grant["version"] + 1
        conn.execute(
            "UPDATE grants SET active = 0, version = ? WHERE resource_id = ? AND recipient_id = ?",
            (version, resource_id, recipient_id),
        )
        return version

    @staticmethod
    def _receipt_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "transaction_id": row["transaction_id"],
            "block_height": row["block_height"],
            "block_hash": row["block_hash"],
            "operation": row["operation"],
            "resource_id": row["resource_id"],
            "version": row["version"],
        }

    def submit(self, transaction: dict[str, Any]) -> dict[str, Any]:
        """Validate and atomically append a signed transaction, returning its receipt."""

        if type(transaction) is not dict or "transaction_id" not in transaction:
            raise LedgerError("INVALID_TRANSACTION", "Transaction fields do not match schema v2")
        transaction_id = _require_uuid(transaction["transaction_id"], "transaction_id")
        transaction_json = canonical_json(transaction).decode("utf-8")
        try:
            with self._connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT * FROM transactions WHERE transaction_id = ?", (transaction_id,)
                ).fetchone()
                if existing is not None:
                    if existing["transaction_json"] != transaction_json:
                        raise LedgerError(
                            "TRANSACTION_ID_CONFLICT",
                            "Transaction ID is already committed with different content",
                        )
                    receipt = self._receipt_from_row(existing)
                    conn.commit()
                    return receipt

                now = int(time.time())
                self._assert_clock(conn, now)
                validated = self._validate_for_chain(transaction, now, check_freshness=True)
                signer_id = validated["signer_id"]
                nonce_row = conn.execute(
                    "SELECT nonce FROM signer_nonces WHERE signer_id = ?", (signer_id,)
                ).fetchone()
                expected_nonce = 1 if nonce_row is None else nonce_row["nonce"] + 1
                if validated["nonce"] != expected_nonce:
                    raise LedgerError(
                        "NONCE_MISMATCH", "Transaction nonce is not the next signer nonce"
                    )

                version = self._apply_new_transaction(conn, validated, now)
                head_height_row = conn.execute(
                    "SELECT value FROM ledger_meta WHERE key = 'head_height'"
                ).fetchone()
                head_hash_row = conn.execute(
                    "SELECT value FROM ledger_meta WHERE key = 'head_hash'"
                ).fetchone()
                if head_height_row is None or head_hash_row is None:
                    raise LedgerError("LEDGER_CORRUPT", "Ledger head is missing")
                height = int(head_height_row[0]) + 1
                previous_hash = head_hash_row[0]
                block_body = {
                    "height": height,
                    "previous_hash": previous_hash,
                    "committed_at": now,
                    "transaction": validated,
                }
                block_hash = _sha256_hex(block_body)
                validator_signature = self._validator_private_key.sign(bytes.fromhex(block_hash))
                block = {
                    **block_body,
                    "block_hash": block_hash,
                    "validator_signature_b64": base64.b64encode(validator_signature).decode(
                        "ascii"
                    ),
                }
                block_json = canonical_json(block).decode("utf-8")
                resource_id = validated["payload"]["resource_id"]

                conn.execute(
                    "INSERT INTO blocks (height, previous_hash, committed_at, block_hash, transaction_id, block_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (height, previous_hash, now, block_hash, transaction_id, block_json),
                )
                conn.execute(
                    "INSERT INTO transactions (transaction_id, transaction_json, block_height, block_hash, operation, resource_id, version) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        transaction_id,
                        transaction_json,
                        height,
                        block_hash,
                        validated["operation"],
                        resource_id,
                        version,
                    ),
                )
                conn.execute(
                    "INSERT INTO signer_nonces (signer_id, nonce) VALUES (?, ?) "
                    "ON CONFLICT(signer_id) DO UPDATE SET nonce = excluded.nonce",
                    (signer_id, validated["nonce"]),
                )
                conn.execute(
                    "UPDATE ledger_meta SET value = ? WHERE key = 'head_height'", (str(height),)
                )
                conn.execute(
                    "UPDATE ledger_meta SET value = ? WHERE key = 'head_hash'", (block_hash,)
                )
                conn.execute(
                    "UPDATE ledger_meta SET value = ? WHERE key = 'clock_watermark'", (str(now),)
                )
                self._before_commit()
                conn.commit()
                self._after_commit()
                return {
                    "transaction_id": transaction_id,
                    "block_height": height,
                    "block_hash": block_hash,
                    "operation": validated["operation"],
                    "resource_id": resource_id,
                    "version": version,
                }
        except LedgerError:
            raise
        except sqlite3.Error as exc:
            raise LedgerError("LEDGER_STORAGE_ERROR", "Ledger storage operation failed") from exc
        except Exception as exc:
            # An exception after commit can mean the receipt was committed. Exact retry is safe.
            raise LedgerError(
                "LEDGER_COMMIT_FAILED", "Ledger transaction did not return a confirmed receipt"
            ) from exc

    def receipt(self, transaction_id: str) -> dict[str, Any] | None:
        _require_uuid(transaction_id, "transaction_id", code="INVALID_TRANSACTION")
        try:
            with self._connection() as conn:
                conn.execute("BEGIN")
                row = conn.execute(
                    "SELECT transaction_id, block_height, block_hash, operation, resource_id, version "
                    "FROM transactions WHERE transaction_id = ?",
                    (transaction_id,),
                ).fetchone()
                conn.commit()
                return None if row is None else self._receipt_from_row(row)
        except sqlite3.Error as exc:
            raise LedgerError("LEDGER_STORAGE_ERROR", "Ledger storage operation failed") from exc

    def next_nonce(self, signer_id: str) -> int:
        _require_uuid(signer_id, "signer_id", code="INVALID_SIGNER")
        if signer_id not in self._identity_keys:
            raise LedgerError("IDENTITY_NOT_PROVISIONED", "Signer is not provisioned")
        try:
            with self._connection() as conn:
                conn.execute("BEGIN")
                row = conn.execute(
                    "SELECT nonce FROM signer_nonces WHERE signer_id = ?", (signer_id,)
                ).fetchone()
                conn.commit()
                return 1 if row is None else row["nonce"] + 1
        except sqlite3.Error as exc:
            raise LedgerError("LEDGER_STORAGE_ERROR", "Ledger storage operation failed") from exc

    def state(self, resource_id: str, recipient_id: str, challenge: str) -> dict[str, Any]:
        """Return a validator-signed observation of current resource/grant state."""

        _require_resource_id(resource_id, code="INVALID_STATE_REQUEST")
        _require_uuid(recipient_id, "recipient_id", code="INVALID_STATE_REQUEST")
        if not isinstance(challenge, str) or not challenge or len(challenge) > 256:
            raise LedgerError(
                "INVALID_STATE_REQUEST",
                "challenge must be a non-empty string of at most 256 characters",
            )
        if recipient_id not in self._identity_keys:
            raise LedgerError(
                "RECIPIENT_NOT_PROVISIONED", "Observation recipient is not provisioned"
            )

        now = int(time.time())
        try:
            with self._connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._assert_clock(conn, now)
                resource = conn.execute(
                    "SELECT owner_id FROM resources WHERE resource_id = ?", (resource_id,)
                ).fetchone()
                owner_id = None if resource is None else resource["owner_id"]
                if owner_id is not None and recipient_id == owner_id:
                    raise LedgerError("OWNER_CANNOT_BE_READER", "Resource owner cannot be a reader")

                grant_row = None
                if owner_id is not None:
                    grant_row = conn.execute(
                        "SELECT recipient_id, policy_digest, expires_at, scope, active, version FROM grants "
                        "WHERE resource_id = ? AND recipient_id = ?",
                        (resource_id, recipient_id),
                    ).fetchone()
                grant = None
                if grant_row is not None:
                    grant = {
                        "recipient_id": grant_row["recipient_id"],
                        "policy_digest": grant_row["policy_digest"],
                        "expires_at": grant_row["expires_at"],
                        "scope": grant_row["scope"],
                        "active": bool(grant_row["active"] == 1 and grant_row["expires_at"] > now),
                        "version": grant_row["version"],
                    }

                head_height_row = conn.execute(
                    "SELECT value FROM ledger_meta WHERE key = 'head_height'"
                ).fetchone()
                head_hash_row = conn.execute(
                    "SELECT value FROM ledger_meta WHERE key = 'head_hash'"
                ).fetchone()
                if head_height_row is None or head_hash_row is None:
                    raise LedgerError("LEDGER_CORRUPT", "Ledger head is missing")
                observed = {
                    "chain_id": self.chain_id,
                    "genesis_hash": self._genesis_hash,
                    "challenge": challenge,
                    "observed_at": now,
                    "head_height": int(head_height_row[0]),
                    "head_hash": head_hash_row[0],
                    "resource_id": resource_id,
                    "owner_id": owner_id,
                    "recipient_id": recipient_id,
                    "grant": grant,
                }
                conn.execute(
                    "UPDATE ledger_meta SET value = ? WHERE key = 'clock_watermark'", (str(now),)
                )
                conn.commit()
                signature = self._validator_private_key.sign(canonical_json(observed))
                return {**observed, "signature_b64": base64.b64encode(signature).decode("ascii")}
        except LedgerError:
            raise
        except sqlite3.Error as exc:
            raise LedgerError("LEDGER_STORAGE_ERROR", "Ledger storage operation failed") from exc

    def verify(self) -> dict[str, Any]:
        """Replay all blocks and reject any mismatch with the materialized indexes."""

        try:
            with self._connection() as conn:
                if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                    raise LedgerError(
                        "LEDGER_SCHEMA_UNSUPPORTED", "Ledger database schema version is unsupported"
                    )
                conn.execute("BEGIN")
                self._check_pinned_config(conn)
                meta = dict(conn.execute("SELECT key, value FROM ledger_meta").fetchall())
                if meta.get("genesis_hash") != self._genesis_hash:
                    raise LedgerError(
                        "LEDGER_CORRUPT", "Ledger genesis does not match pinned configuration"
                    )
                try:
                    clock_watermark = int(meta["clock_watermark"])
                    recorded_head_height = int(meta["head_height"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise LedgerError("LEDGER_CORRUPT", "Ledger metadata is invalid") from exc
                if clock_watermark < 0:
                    raise LedgerError("LEDGER_CORRUPT", "Ledger clock state is invalid")

                resource_state: dict[str, dict[str, Any]] = {}
                grant_state: dict[tuple[str, str], dict[str, Any]] = {}
                nonces: dict[str, int] = {}
                expected_receipts: dict[str, dict[str, Any]] = {}
                previous_hash = self._genesis_hash
                previous_committed_at = 0
                blocks = conn.execute("SELECT * FROM blocks ORDER BY height").fetchall()
                if recorded_head_height != len(blocks):
                    raise LedgerError(
                        "LEDGER_CORRUPT", "Ledger head height does not match block history"
                    )

                for expected_height, row in enumerate(blocks, start=1):
                    try:
                        block = json.loads(row["block_json"])
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise LedgerError("LEDGER_CORRUPT", "Stored block JSON is invalid") from exc
                    if type(block) is not dict or set(block) != BLOCK_KEYS:
                        raise LedgerError(
                            "LEDGER_CORRUPT", "Stored block fields do not match schema v2"
                        )
                    if canonical_json(block).decode("utf-8") != row["block_json"]:
                        raise LedgerError("LEDGER_CORRUPT", "Stored block is not canonical JSON")
                    if (
                        type(block["height"]) is not int
                        or block["height"] != expected_height
                        or row["height"] != expected_height
                    ):
                        raise LedgerError("LEDGER_CORRUPT", "Block heights are not contiguous")
                    if (
                        block["previous_hash"] != previous_hash
                        or row["previous_hash"] != previous_hash
                    ):
                        raise LedgerError(
                            "LEDGER_CORRUPT", "Block previous hash does not match history"
                        )
                    committed_at = _require_int(
                        block["committed_at"], "committed_at", minimum=1, code="LEDGER_CORRUPT"
                    )
                    if committed_at < previous_committed_at:
                        raise LedgerError("LEDGER_CORRUPT", "Block commit times moved backwards")
                    transaction = _validate_transaction_shape(block["transaction"])
                    if transaction["chain_id"] != self.chain_id:
                        raise LedgerError(
                            "LEDGER_CORRUPT", "Stored transaction targets a different chain"
                        )
                    self._verify_transaction_signature(transaction)
                    if abs(transaction["issued_at"] - committed_at) > MAX_TX_AGE_SECONDS:
                        raise LedgerError(
                            "LEDGER_CORRUPT", "Stored transaction was not fresh at commit"
                        )
                    transaction_id = transaction["transaction_id"]
                    signer_id = transaction["signer_id"]
                    expected_nonce = nonces.get(signer_id, 0) + 1
                    if transaction["nonce"] != expected_nonce:
                        raise LedgerError(
                            "LEDGER_CORRUPT", "Stored signer nonce sequence is invalid"
                        )
                    nonces[signer_id] = expected_nonce

                    operation = transaction["operation"]
                    payload = transaction["payload"]
                    resource_id = payload["resource_id"]
                    version = self._apply_history_transaction(
                        resource_state, grant_state, signer_id, operation, payload
                    )

                    block_body = {
                        "height": expected_height,
                        "previous_hash": previous_hash,
                        "committed_at": committed_at,
                        "transaction": transaction,
                    }
                    expected_hash = _sha256_hex(block_body)
                    if block["block_hash"] != expected_hash or row["block_hash"] != expected_hash:
                        raise LedgerError("LEDGER_CORRUPT", "Block hash is invalid")
                    validator_signature = _decode_signature(
                        block["validator_signature_b64"], "validator_signature_b64"
                    )
                    try:
                        self._validator_public_key.verify(
                            validator_signature, bytes.fromhex(expected_hash)
                        )
                    except InvalidSignature as exc:
                        raise LedgerError(
                            "LEDGER_CORRUPT", "Validator block signature is invalid"
                        ) from exc
                    if row["transaction_id"] != transaction_id:
                        raise LedgerError("LEDGER_CORRUPT", "Block transaction index is invalid")

                    expected_receipts[transaction_id] = {
                        "transaction_id": transaction_id,
                        "block_height": expected_height,
                        "block_hash": expected_hash,
                        "operation": operation,
                        "resource_id": resource_id,
                        "version": version,
                        "transaction_json": canonical_json(transaction).decode("utf-8"),
                    }
                    previous_hash = expected_hash
                    previous_committed_at = committed_at

                if clock_watermark < previous_committed_at:
                    raise LedgerError(
                        "LEDGER_CORRUPT", "Ledger clock checkpoint predates a confirmed block"
                    )
                if meta.get("head_hash") != previous_hash:
                    raise LedgerError(
                        "LEDGER_CORRUPT", "Ledger head hash does not match block history"
                    )
                self._compare_receipt_index(conn, expected_receipts)
                self._compare_materialized_state(conn, resource_state, grant_state, nonces)
                conn.commit()
                return {
                    "valid": True,
                    "chain_id": self.chain_id,
                    "genesis_hash": self._genesis_hash,
                    "head_height": len(blocks),
                    "head_hash": previous_hash,
                    "transaction_count": len(expected_receipts),
                }
        except LedgerError as exc:
            if exc.code in {"LEDGER_CORRUPT", "LEDGER_SCHEMA_UNSUPPORTED", "CHAIN_CONFIG_MISMATCH"}:
                raise
            raise LedgerError("LEDGER_CORRUPT", "Ledger history failed verification") from exc
        except sqlite3.Error as exc:
            raise LedgerError(
                "LEDGER_CORRUPT", "Ledger database failed history verification"
            ) from exc
        except Exception as exc:
            raise LedgerError("LEDGER_CORRUPT", "Ledger history failed verification") from exc

    @staticmethod
    def _apply_history_transaction(
        resources: dict[str, dict[str, Any]],
        grants: dict[tuple[str, str], dict[str, Any]],
        signer_id: str,
        operation: str,
        payload: dict[str, Any],
    ) -> int:
        resource_id = payload["resource_id"]
        resource = resources.get(resource_id)
        if operation == "REGISTER_RESOURCE":
            if resource is not None:
                raise LedgerError("LEDGER_CORRUPT", "Resource has multiple owners in block history")
            resources[resource_id] = {"owner_id": signer_id, "version": 1}
            return 1
        if resource is None:
            raise LedgerError("LEDGER_CORRUPT", "Grant references an unknown resource")
        if resource["owner_id"] != signer_id:
            raise LedgerError("LEDGER_CORRUPT", "Grant signer is not the immutable owner")
        recipient_id = payload["recipient_id"]
        if recipient_id == resource["owner_id"]:
            raise LedgerError("LEDGER_CORRUPT", "Owner cannot appear as a reader")
        key = (resource_id, recipient_id)
        old = grants.get(key)
        if operation == "GRANT":
            if payload["expires_at"] <= 0 or payload["scope"] != "READ_INSIGHT":
                raise LedgerError("LEDGER_CORRUPT", "Stored grant fields are invalid")
            version = 1 if old is None else old["version"] + 1
            grants[key] = {
                "recipient_id": recipient_id,
                "policy_digest": payload["policy_digest"],
                "expires_at": payload["expires_at"],
                "scope": payload["scope"],
                "active": 1,
                "version": version,
            }
            return version
        if old is None or old["active"] != 1:
            raise LedgerError("LEDGER_CORRUPT", "Stored revoke has no active grant")
        version = old["version"] + 1
        old["active"] = 0
        old["version"] = version
        return version

    @staticmethod
    def _compare_receipt_index(
        conn: sqlite3.Connection, expected: dict[str, dict[str, Any]]
    ) -> None:
        rows = conn.execute("SELECT * FROM transactions ORDER BY block_height").fetchall()
        if len(rows) != len(expected):
            raise LedgerError(
                "LEDGER_CORRUPT", "Transaction index count does not match block history"
            )
        for row in rows:
            receipt = expected.get(row["transaction_id"])
            if receipt is None:
                raise LedgerError(
                    "LEDGER_CORRUPT", "Transaction index contains an unknown transaction"
                )
            for field in (
                "transaction_id",
                "block_height",
                "block_hash",
                "operation",
                "resource_id",
                "version",
                "transaction_json",
            ):
                if row[field] != receipt[field]:
                    raise LedgerError(
                        "LEDGER_CORRUPT", "Transaction index does not match block history"
                    )

    @staticmethod
    def _compare_materialized_state(
        conn: sqlite3.Connection,
        resources: dict[str, dict[str, Any]],
        grants: dict[tuple[str, str], dict[str, Any]],
        nonces: dict[str, int],
    ) -> None:
        stored_resources = {
            row["resource_id"]: {"owner_id": row["owner_id"], "version": row["version"]}
            for row in conn.execute("SELECT * FROM resources")
        }
        if stored_resources != resources:
            raise LedgerError("LEDGER_CORRUPT", "Resource state does not match block history")

        stored_grants = {
            (row["resource_id"], row["recipient_id"]): {
                "recipient_id": row["recipient_id"],
                "policy_digest": row["policy_digest"],
                "expires_at": row["expires_at"],
                "scope": row["scope"],
                "active": row["active"],
                "version": row["version"],
            }
            for row in conn.execute("SELECT * FROM grants")
        }
        if stored_grants != grants:
            raise LedgerError("LEDGER_CORRUPT", "Grant state does not match block history")

        stored_nonces = {
            row["signer_id"]: row["nonce"] for row in conn.execute("SELECT * FROM signer_nonces")
        }
        if stored_nonces != nonces:
            raise LedgerError("LEDGER_CORRUPT", "Signer nonce state does not match block history")


def _status_for_error(code: str) -> int:
    if code in {"RESOURCE_NOT_FOUND", "GRANT_NOT_FOUND", "RECEIPT_NOT_FOUND"}:
        return 404
    if code in {
        "RESOURCE_ALREADY_REGISTERED",
        "TRANSACTION_ID_CONFLICT",
        "NONCE_MISMATCH",
        "GRANT_NOT_ACTIVE",
        "OWNER_CANNOT_BE_READER",
        "GRANT_EXPIRED",
    }:
        return 409
    if code in {"OWNER_REQUIRED", "IDENTITY_NOT_PROVISIONED", "RECIPIENT_NOT_PROVISIONED"}:
        return 403
    if code in {"CLOCK_REGRESSION", "LEDGER_STORAGE_ERROR", "LEDGER_COMMIT_FAILED"}:
        return 503
    return 422


def create_app(ledger: Ledger):
    """Create the standalone local validator FastAPI application."""

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_app: Any):
        ledger.verify()
        yield

    app = FastAPI(title="PrivacyGate v2 local validator", lifespan=lifespan)

    @app.exception_handler(LedgerError)
    async def ledger_error_handler(_request: Request, exc: LedgerError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_error(exc.code),
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    async def read_object(request: Request, expected: set[str] | None = None) -> dict[str, Any]:
        try:
            body = await request.json()
        except Exception as exc:
            raise LedgerError("INVALID_JSON", "Request body must be a JSON object") from exc
        if type(body) is not dict:
            raise LedgerError("INVALID_JSON", "Request body must be a JSON object")
        if expected is not None and set(body) != expected:
            raise LedgerError(
                "INVALID_STATE_REQUEST", "Request fields do not match the endpoint schema"
            )
        return body

    @app.post("/transactions")
    async def post_transaction(request: Request) -> dict[str, Any]:
        body = await read_object(request)
        return ledger.submit(body)

    @app.get("/receipts/{transaction_id}")
    async def get_receipt(transaction_id: str) -> dict[str, Any]:
        receipt = ledger.receipt(transaction_id)
        if receipt is None:
            raise LedgerError("RECEIPT_NOT_FOUND", "Transaction receipt was not found")
        return receipt

    @app.get("/config")
    async def get_config() -> dict[str, Any]:
        return ledger.config

    @app.post("/state")
    async def post_state(request: Request) -> dict[str, Any]:
        body = await read_object(request, {"resource_id", "recipient_id", "challenge"})
        return ledger.state(body["resource_id"], body["recipient_id"], body["challenge"])

    @app.get("/nonces/{signer_id}")
    async def get_nonce(signer_id: str) -> dict[str, Any]:
        return {"signer_id": signer_id, "next_nonce": ledger.next_nonce(signer_id)}

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def _load_ledger_config(config_path: Path) -> Ledger:
    try:
        raw_value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LedgerError("INVALID_CONFIG", "Validator config file could not be read") from exc
    if not isinstance(raw_value, dict):
        raise LedgerError("INVALID_CONFIG", "Validator config must be a JSON object")
    raw: dict[str, Any] = raw_value
    chain_value = raw.get("chain")
    chain: dict[str, Any] = chain_value if isinstance(chain_value, dict) else {}
    private_b64 = raw.get("validator_private_key_b64", chain.get("validator_private_key_b64"))
    identities = raw.get("identities", chain.get("identities"))
    chain_id = raw.get("chain_id", chain.get("chain_id", DEFAULT_CHAIN_ID))
    db_value = raw.get("ledger_db", raw.get("ledger_db_path", raw.get("database_path")))
    if not isinstance(db_value, str) or not db_value:
        raise LedgerError("INVALID_CONFIG", "Validator config must include ledger_db")
    if not isinstance(private_b64, str) or not isinstance(identities, dict):
        raise LedgerError(
            "INVALID_CONFIG", "Validator config is missing signing key or pinned identities"
        )
    if not isinstance(chain_id, str):
        raise LedgerError("INVALID_CONFIG", "Validator config has an invalid chain_id")

    db_path = Path(db_value).expanduser()
    if not db_path.is_absolute():
        # Config paths are relative to the process working directory, matching the repo's var/v2 paths.
        db_path = Path.cwd() / db_path
    ledger = Ledger(db_path, private_b64, identities, chain_id)

    configured_public = raw.get("validator_public_key_b64", chain.get("validator_public_key_b64"))
    if (
        configured_public is not None
        and configured_public != ledger.config["validator_public_key_b64"]
    ):
        raise LedgerError(
            "CHAIN_CONFIG_MISMATCH", "Configured validator public key does not match private key"
        )
    configured_genesis = raw.get("genesis_hash", chain.get("genesis_hash"))
    if configured_genesis is not None and configured_genesis != ledger.config["genesis_hash"]:
        raise LedgerError("CHAIN_CONFIG_MISMATCH", "Configured genesis hash does not match ledger")
    return ledger


def main(config_path: str | os.PathLike[str] | None = None) -> None:
    """Run the validator on loopback using a JSON config file."""

    if config_path is None:
        parser = argparse.ArgumentParser(description="Run the PrivacyGate v2 local validator")
        parser.add_argument(
            "--config", default="var/v2/config.json", help="validator JSON config path"
        )
        args = parser.parse_args()
        config_path = args.config
    ledger = _load_ledger_config(Path(config_path).expanduser().resolve())
    try:
        import uvicorn
    except ImportError as exc:
        raise LedgerError(
            "VALIDATOR_DEPENDENCY_MISSING", "Install uvicorn to run the validator service"
        ) from exc
    uvicorn.run(create_app(ledger), host="127.0.0.1", port=8010, log_level="info")


if __name__ == "__main__":
    main()
