"""Durable gateway orchestration; the predictor never decides authorization."""

import json
import os
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .model import MODEL_VERSION, AnomalyModel
from .repository import Repository
from .schemas import SignedReading, iso_now, resource_string, uuid_string
from .security import b64, canonical, digest, encrypt_envelope, hash_password, unb64


class GatewayError(Exception):
    def __init__(self, code: str, status: int = 403, message: str = "Access not allowed"):
        self.code, self.status, self.message = code, status, message
        super().__init__(code)


def load_config(value: dict | str | Path | None = None) -> dict:
    if value is None:
        value = os.environ.get("PG_V2_CONFIG")
    if value is None:
        raise RuntimeError("PG_V2_CONFIG is required")
    config = (
        dict(value) if isinstance(value, dict) else json.loads(Path(value).read_text("utf-8-sig"))
    )
    root = Path(config["runtime_root"]).resolve()
    config["runtime_root"] = str(root)
    config.setdefault("database_path", str(root / "gateway.db"))
    config.setdefault("origin", "http://127.0.0.1:3000")
    unb64(config["raw_key_b64"], 32)
    if not config["origin"].startswith(("http://127.0.0.1:", "http://localhost:", "https://")):
        raise RuntimeError("Invalid configured origin")
    return config


def initialize_accounts(config: dict | str | Path) -> None:
    """Create immutable bootstrap identities, storing password hashes only.

    Existing matching identities are untouched. Different account IDs/usernames/roles
    are rejected rather than silently replacing the identity or its password.
    Ordinary startup can omit accounts after running this once.
    """
    config = load_config(config)
    repo = Repository(config["database_path"])
    for account in config.get("accounts", []):
        uuid_string(account["account_id"])
        if (
            account["role"] not in {"owner", "reader"}
            or not account["username"]
            or len(account["username"]) > 80
            or len(account["password"]) < 12
        ):
            raise ValueError("Invalid bootstrap account")
        if account["account_id"] not in config["chain"]["identities"]:
            raise ValueError("Account is not pinned on chain")
        existing = repo.one(
            "SELECT * FROM accounts WHERE account_id=? OR username=?",
            (account["account_id"], account["username"]),
        )
        if existing:
            if any(existing[k] != account[k] for k in ("account_id", "username", "role")):
                raise ValueError("Immutable account conflict")
            continue
        repo.execute(
            "INSERT INTO accounts VALUES(?,?,?,?)",
            (
                account["account_id"],
                account["username"],
                account["role"],
                hash_password(account["password"]),
            ),
        )


class Gateway:
    def __init__(self, config: dict | str | Path, ledger_client: Any = None):
        self.config = load_config(config)
        initialize_accounts(self.config)
        self.repo = Repository(self.config["database_path"])
        self.repo.cleanup()
        self.raw_cipher = AESGCM(unb64(self.config["raw_key_b64"], 32))
        self.key_dir = Path(self.config["runtime_root"]) / "device_keys"
        self.key_dir.mkdir(parents=True, exist_ok=True)
        if ledger_client is None:
            from .ledger_client import LedgerClient

            ledger_client = LedgerClient(
                self.config["chain"]["url"],
                self.config["chain"],
                checkpoint_path=Path(self.config["runtime_root"]) / "head.json",
            )
        self.chain = ledger_client
        self.model = AnomalyModel()
        self._signer_locks: dict[str, threading.RLock] = {}
        self._device_locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()
        self.dummy_password = hash_password(secrets.token_urlsafe(24))
        # Pending operations are reconciled lazily, so an outage cannot prevent ingestion.

    def lock(self, group: str, identifier: str):
        with self._locks_guard:
            locks = self._signer_locks if group == "signer" else self._device_locks
            return locks.setdefault(identifier, threading.RLock())

    def account(self, account_id: str) -> dict:
        account = self.repo.one(
            "SELECT account_id,username,role FROM accounts WHERE account_id=?", (account_id,)
        )
        if not account:
            raise GatewayError("UNAUTHENTICATED", 401)
        return account

    def rate_limit(self, bucket: str, maximum: int, seconds: int):
        now = int(time.time())
        with self.repo.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM login_attempts WHERE bucket=?", (bucket,)).fetchone()
            if row and row["window_start"] > now - seconds:
                if row["count"] >= maximum:
                    raise GatewayError("RATE_LIMITED", 429, "Request limit reached")
                db.execute("UPDATE login_attempts SET count=count+1 WHERE bucket=?", (bucket,))
            else:
                db.execute("INSERT OR REPLACE INTO login_attempts VALUES(?,?,1)", (bucket, now))

    def owned_device(self, resource_id: str, account: dict) -> dict:
        if account["role"] != "owner":
            raise GatewayError("OWNER_REQUIRED")
        try:
            resource_string(resource_id)
        except ValueError:
            raise GatewayError("NOT_FOUND", 404) from None
        device = self.repo.one(
            "SELECT * FROM devices WHERE resource_id=? AND owner_id=?",
            (resource_id, account["account_id"]),
        )
        if not device:
            raise GatewayError("NOT_FOUND", 404)
        if not device["registered"]:
            raise GatewayError("DEVICE_UNCONFIRMED", 409, "Device registration is not confirmed")
        return device

    @staticmethod
    def device_view(device: dict) -> dict:
        return {
            key: device[key]
            for key in (
                "resource_id",
                "device_id",
                "name",
                "ed25519_public_key_b64",
                "last_sequence",
            )
        }

    def _commit(self, operation: dict) -> dict:
        transaction = json.loads(operation["transaction_json"])
        if operation["receipt_json"]:
            saved = json.loads(operation["receipt_json"])
            if saved.get("failure_code"):
                raise GatewayError(
                    "OPERATION_EXPIRED", 409, "Operation expired; start a new operation"
                )
            return saved
        try:
            receipt = self.chain.receipt(operation["transaction_id"])
            if receipt is None:
                self.expire_uncommitted(operation, transaction)
                receipt = self.chain.submit(transaction)
            if (
                receipt["transaction_id"] != transaction["transaction_id"]
                or receipt["operation"] != transaction["operation"]
                or receipt["resource_id"] != transaction["payload"]["resource_id"]
            ):
                raise ValueError("Receipt mismatch")
            self.repo.finalize(operation["transaction_id"], receipt)
            return receipt
        except Exception as exc:
            if isinstance(exc, GatewayError):
                raise
            raise GatewayError(
                "AUTHZ_UNAVAILABLE", 503, "Confirmed chain state unavailable"
            ) from None

    def reconcile(self, signer_id: str):
        with self.lock("signer", signer_id):
            pending = self.repo.all(
                "SELECT * FROM outbox WHERE signer_id=? AND receipt_json IS NULL "
                "ORDER BY created_at,rowid",
                (signer_id,),
            )
            for operation in pending:
                try:
                    self._commit(operation)
                except GatewayError as exc:
                    if exc.code != "OPERATION_EXPIRED":
                        raise

    def expire_uncommitted(self, operation: dict, transaction: dict):
        """Retain stale signed bytes; unblock new writes only after signed-time proof."""
        if int(time.time()) <= transaction["issued_at"] + 35:
            return
        recipient = transaction["payload"].get("recipient_id", transaction["signer_id"])
        observation = self.chain.state(transaction["payload"]["resource_id"], recipient)
        if observation["observed_at"] <= transaction["issued_at"] + 35:
            return
        if transaction["operation"] == "REGISTER_RESOURCE" and (
            observation["owner_id"] is not None or observation["grant"] is not None
        ):
            return
        if self.chain.next_nonce(transaction["signer_id"]) != transaction["nonce"]:
            return
        with self.repo.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE outbox SET receipt_json=? WHERE transaction_id=? AND receipt_json IS NULL",
                (
                    canonical({"failure_code": "OPERATION_EXPIRED"}).decode(),
                    transaction["transaction_id"],
                ),
            ).rowcount
            if changed and operation["operation"] == "GRANT":
                db.execute(
                    "UPDATE policies SET status='FAILED' WHERE policy_id=? AND status='PENDING'",
                    (operation["entity_id"],),
                )
            elif changed and operation["operation"] == "REVOKE":
                db.execute(
                    "UPDATE policies SET status='ACTIVE' WHERE policy_id=? AND status='PENDING_REVOKE'",
                    (operation["entity_id"],),
                )
        raise GatewayError("OPERATION_EXPIRED", 409, "Operation expired; start a new operation")

    def transaction(
        self, signer_id: str, operation: str, payload: dict, transaction_id: str | None = None
    ) -> dict:
        from .ledger import sign_transaction

        try:
            nonce = self.chain.next_nonce(signer_id)
            return sign_transaction(
                self.config["owner_private_keys"][signer_id],
                self.config["chain"]["chain_id"],
                signer_id,
                nonce,
                operation,
                payload,
                transaction_id=transaction_id,
            )
        except Exception:  # noqa: BLE001 - every uncertain chain failure must deny disclosure
            raise GatewayError(
                "AUTHZ_UNAVAILABLE", 503, "Confirmed chain state unavailable"
            ) from None

    @staticmethod
    def save_operation(db, tx: dict, entity_id: str, request_digest: str):
        db.execute(
            "INSERT INTO outbox VALUES(?,?,?,?,?,?,?,?)",
            (
                tx["transaction_id"],
                tx["signer_id"],
                tx["operation"],
                entity_id,
                canonical(tx).decode(),
                None,
                int(time.time()),
                request_digest,
            ),
        )

    def retry_operation(
        self, account: dict, operation_id: str | None, operation: str, fingerprint: str
    ):
        if operation_id is None:
            return None
        try:
            uuid_string(operation_id)
        except ValueError:
            raise GatewayError(
                "INVALID_OPERATION_ID", 422, "Canonical operation UUID required"
            ) from None
        row = self.repo.one("SELECT * FROM outbox WHERE transaction_id=?", (operation_id,))
        if not row:
            return None
        if (
            row["signer_id"] != account["account_id"]
            or row["operation"] != operation
            or row["request_digest"] != fingerprint
        ):
            raise GatewayError(
                "OPERATION_CONFLICT", 409, "Operation does not match original request"
            )
        receipt = self._commit(row)
        if operation == "REGISTER_RESOURCE":
            device = self.repo.one("SELECT * FROM devices WHERE resource_id=?", (row["entity_id"],))
            return {**self.device_view(device), "receipt": receipt}
        return self.policy_view(
            self.repo.one("SELECT * FROM policies WHERE policy_id=?", (row["entity_id"],))
        )

    def register_device(self, account: dict, name: str, operation_id: str | None = None) -> dict:
        if account["role"] != "owner":
            raise GatewayError("OWNER_REQUIRED")
        signer = account["account_id"]
        fingerprint = digest(canonical({"name": name}))
        with self.lock("signer", signer):
            retried = self.retry_operation(account, operation_id, "REGISTER_RESOURCE", fingerprint)
            if retried is not None:
                return retried
            self.reconcile(signer)
            resource_id, device_id = "0x" + secrets.token_hex(32), str(uuid4())
            private = Ed25519PrivateKey.generate()
            device = {
                "resource_id": resource_id,
                "device_id": device_id,
                "name": name,
                "ed25519_public_key_b64": b64(private.public_key().public_bytes_raw()),
                "last_sequence": 0,
            }
            tx = self.transaction(
                signer, "REGISTER_RESOURCE", {"resource_id": resource_id}, operation_id
            )
            nonce = os.urandom(12)
            # Crash before DB commit leaves an inert orphan key; never an unpinned device.
            with (self.key_dir / f"{device_id}.key").open("xb") as key_file:
                key_file.write(
                    nonce
                    + self.raw_cipher.encrypt(
                        nonce, private.private_bytes_raw(), device_id.encode()
                    )
                )
                key_file.flush()
                os.fsync(key_file.fileno())
            with self.repo.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO devices VALUES(?,?,?,?,?,0,0)",
                    (resource_id, signer, device_id, name, device["ed25519_public_key_b64"]),
                )
                self.save_operation(db, tx, resource_id, fingerprint)
            operation = self.repo.one(
                "SELECT * FROM outbox WHERE transaction_id=?", (tx["transaction_id"],)
            )
            return {**device, "receipt": self._commit(operation)}

    def enroll_key(self, account: dict, public: str, replace: bool) -> dict:
        if account["role"] != "reader":
            raise GatewayError("READER_REQUIRED")
        try:
            parsed = X25519PublicKey.from_public_bytes(unb64(public, 32))
            X25519PrivateKey.generate().exchange(parsed)  # reject low-order/all-zero keys
        except (ValueError, TypeError):
            raise GatewayError("INVALID_KEY", 422, "Invalid public key") from None
        with self.repo.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM reader_keys WHERE account_id=?", (account["account_id"],)
            ).fetchone()
            if row and row["x25519_public_key_b64"] == public:
                return {k: row[k] for k in ("key_id", "key_version", "x25519_public_key_b64")}
            if row and not replace:
                raise GatewayError(
                    "KEY_REPLACEMENT_REQUIRED", 409, "Explicit key replacement required"
                )
            key = {
                "key_id": str(uuid4()),
                "key_version": row["key_version"] + 1 if row else 1,
                "x25519_public_key_b64": public,
            }
            db.execute(
                "INSERT OR REPLACE INTO reader_keys VALUES(?,?,?,?)",
                (account["account_id"], key["key_id"], key["key_version"], public),
            )
            db.execute("DELETE FROM deliveries WHERE recipient_id=?", (account["account_id"],))
            return key

    @staticmethod
    def policy_view(policy: dict) -> dict:
        return {
            **{
                k: policy[k]
                for k in (
                    "policy_id",
                    "policy_digest",
                    "resource_id",
                    "recipient_id",
                    "expires_at",
                    "status",
                    "version",
                )
            },
            "receipt": json.loads(policy["receipt_json"]) if policy["receipt_json"] else None,
        }

    def create_policy(self, account: dict, body: dict, operation_id: str | None = None) -> dict:
        self.owned_device(body["resource_id"], account)
        signer = account["account_id"]
        fingerprint = digest(canonical(body))
        with self.lock("signer", signer):
            retried = self.retry_operation(account, operation_id, "GRANT", fingerprint)
            if retried is not None:
                return retried
            recipient = self.repo.one(
                "SELECT role FROM accounts WHERE account_id=?", (body["recipient_id"],)
            )
            if (
                not recipient
                or recipient["role"] != "reader"
                or body["expires_at"] <= int(time.time())
            ):
                raise GatewayError("INVALID_POLICY", 422, "Invalid policy")
            self.reconcile(signer)
            policy_id = str(uuid4())
            manifest = {
                "schema_version": 2,
                "policy_id": policy_id,
                **body,
                "scope": "READ_INSIGHT",
                "event_type": "MACHINE_ANOMALY",
                "fields": ["event_id", "event_type", "severity", "observed_at", "model_version"],
            }
            policy_digest = digest(canonical(manifest))
            tx = self.transaction(
                signer,
                "GRANT",
                {**body, "policy_digest": policy_digest, "scope": "READ_INSIGHT"},
                operation_id,
            )
            with self.repo.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO policies VALUES(?,?,?,?,?,?,'PENDING',0,NULL,?)",
                    (
                        policy_id,
                        signer,
                        body["resource_id"],
                        body["recipient_id"],
                        body["expires_at"],
                        policy_digest,
                        int(time.time()),
                    ),
                )
                self.save_operation(db, tx, policy_id, fingerprint)
            self._commit(
                self.repo.one(
                    "SELECT * FROM outbox WHERE transaction_id=?", (tx["transaction_id"],)
                )
            )
            return self.policy_view(
                self.repo.one("SELECT * FROM policies WHERE policy_id=?", (policy_id,))
            )

    def revoke(self, account: dict, policy_id: str, operation_id: str | None = None) -> dict:
        if account["role"] != "owner":
            raise GatewayError("OWNER_REQUIRED")
        signer = account["account_id"]
        fingerprint = digest(canonical({"policy_id": policy_id}))
        with self.lock("signer", signer):
            retried = self.retry_operation(account, operation_id, "REVOKE", fingerprint)
            if retried is not None:
                return retried
            self.reconcile(signer)
            policy = self.repo.one(
                "SELECT * FROM policies WHERE policy_id=? AND owner_id=?", (policy_id, signer)
            )
            if not policy:
                raise GatewayError("NOT_FOUND", 404)
            if policy["status"] == "REVOKED":
                return self.policy_view(policy)
            observation = self.chain_state(policy["resource_id"], policy["recipient_id"])
            grant = observation["grant"]
            if not grant or grant["policy_digest"] != policy["policy_digest"]:
                raise GatewayError("POLICY_SUPERSEDED", 409, "Policy is no longer current")
            tx = self.transaction(
                signer,
                "REVOKE",
                {"resource_id": policy["resource_id"], "recipient_id": policy["recipient_id"]},
                operation_id,
            )
            with self.repo.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                self.save_operation(db, tx, policy_id, fingerprint)
                db.execute(
                    "UPDATE policies SET status='PENDING_REVOKE' WHERE policy_id=?", (policy_id,)
                )
            self._commit(
                self.repo.one(
                    "SELECT * FROM outbox WHERE transaction_id=?", (tx["transaction_id"],)
                )
            )
            return self.policy_view(
                self.repo.one("SELECT * FROM policies WHERE policy_id=?", (policy_id,))
            )

    def chain_state(self, resource_id: str, recipient_id: str) -> dict:
        try:
            return self.chain.state(resource_id, recipient_id)
        except Exception:  # noqa: BLE001 - injected and HTTP chain clients fail closed alike
            raise GatewayError(
                "AUTHZ_UNAVAILABLE", 503, "Confirmed chain state unavailable"
            ) from None

    def authorized(self, policy: dict, observation: dict, version: int | None = None) -> bool:
        grant = observation.get("grant")
        return bool(
            grant
            and observation["resource_id"] == policy["resource_id"]
            and observation["owner_id"] == policy["owner_id"]
            and observation["recipient_id"] == policy["recipient_id"]
            and grant["recipient_id"] == policy["recipient_id"]
            and grant["active"] is True
            and grant["scope"] == "READ_INSIGHT"
            and grant["expires_at"] > int(time.time())
            and grant["expires_at"] == policy["expires_at"]
            and grant["policy_digest"] == policy["policy_digest"]
            and grant["version"] == (policy["version"] if version is None else version)
            and policy["version"] > 0
        )

    def list_policies(self, account: dict, resource_id: str) -> list:
        self.owned_device(resource_id, account)
        self.reconcile(account["account_id"])
        policies = self.repo.all(
            "SELECT * FROM policies WHERE resource_id=? ORDER BY created_at, rowid", (resource_id,)
        )
        for policy in policies:
            if policy["status"] == "FAILED":
                continue
            observation = self.chain_state(resource_id, policy["recipient_id"])
            grant = observation["grant"]
            if grant and grant["policy_digest"] == policy["policy_digest"]:
                status = (
                    "REVOKED"
                    if not grant["active"]
                    else ("EXPIRED" if grant["expires_at"] <= int(time.time()) else "ACTIVE")
                )
            else:
                status = "SUPERSEDED"
            policy["status"] = status
            self.repo.execute(
                "UPDATE policies SET status=? WHERE policy_id=?", (status, policy["policy_id"])
            )
        return [self.policy_view(p) for p in policies]

    def ingest(self, packet: dict) -> int:
        try:
            if len(canonical(packet)) > 4096:
                raise ValueError("Packet size")
            reading = SignedReading.model_validate(packet)
            timestamp = datetime.fromisoformat(reading.issued_at).timestamp()
            if abs(time.time() - timestamp) > 30:
                raise ValueError("Stale")
            signed = {key: value for key, value in packet.items() if key != "signature_b64"}
            device = self.repo.one(
                "SELECT * FROM devices WHERE resource_id=? AND device_id=? AND registered=1",
                (reading.resource_id, reading.device_id),
            )
            if not device:
                raise ValueError("Device")
            Ed25519PublicKey.from_public_bytes(unb64(device["ed25519_public_key_b64"], 32)).verify(
                unb64(reading.signature_b64, 64), canonical(signed)
            )
        except (ValueError, TypeError, InvalidSignature, OverflowError):
            raise GatewayError("INVALID_READING", 422, "Reading rejected") from None
        raw = {
            k: signed[k]
            for k in ("device_id", "sequence", "issued_at", "temp_c", "vibration_mm_s", "rpm")
        }
        aad = canonical(
            {
                "resource_id": reading.resource_id,
                "device_id": reading.device_id,
                "sequence": reading.sequence,
            }
        )
        nonce = os.urandom(12)
        ciphertext = self.raw_cipher.encrypt(nonce, canonical(raw), aad)
        with self.repo.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE devices SET last_sequence=? WHERE device_id=? AND last_sequence<?",
                (reading.sequence, reading.device_id, reading.sequence),
            ).rowcount
            if changed != 1:
                raise GatewayError("REPLAYED_READING", 409, "Reading rejected")
            db.execute(
                "INSERT INTO telemetry(resource_id,device_id,sequence,accepted_at,nonce,ciphertext) VALUES(?,?,?,?,?,?)",
                (
                    reading.resource_id,
                    reading.device_id,
                    reading.sequence,
                    int(time.time()),
                    nonce,
                    ciphertext,
                ),
            )
        severity = self.model.classify(raw)
        if severity is None:
            return 0
        insight = {
            "event_id": str(uuid4()),
            "event_type": "MACHINE_ANOMALY",
            "severity": severity,
            "observed_at": reading.issued_at,
            "model_version": MODEL_VERSION,
        }
        deliveries = 0
        policies = self.repo.all(
            "SELECT * FROM policies WHERE resource_id=? AND status IN ('ACTIVE','PENDING_REVOKE')",
            (reading.resource_id,),
        )
        for policy in policies:
            try:
                observation = self.chain_state(reading.resource_id, policy["recipient_id"])
                if not self.authorized(policy, observation):
                    continue
                key = self.repo.one(
                    "SELECT * FROM reader_keys WHERE account_id=?", (policy["recipient_id"],)
                )
                if not key:
                    continue
                envelope = encrypt_envelope(
                    insight,
                    reading.resource_id,
                    policy["recipient_id"],
                    policy["version"],
                    key,
                    str(uuid4()),
                )
                with self.repo.connection() as db:
                    db.execute("BEGIN IMMEDIATE")
                    current_key = db.execute(
                        "SELECT key_version FROM reader_keys WHERE account_id=?",
                        (policy["recipient_id"],),
                    ).fetchone()
                    if current_key["key_version"] != key["key_version"]:
                        continue
                    db.execute(
                        "INSERT INTO deliveries(delivery_id,resource_id,recipient_id,policy_digest,policy_version,key_version,created_at,envelope_json) VALUES(?,?,?,?,?,?,?,?)",
                        (
                            envelope["delivery_id"],
                            reading.resource_id,
                            policy["recipient_id"],
                            policy["policy_digest"],
                            policy["version"],
                            key["key_version"],
                            int(time.time()),
                            canonical(envelope).decode(),
                        ),
                    )
                deliveries += 1
            except GatewayError:
                continue  # chain outage suspends disclosure; signed ingestion remains available
        return deliveries

    def simulate(self, account: dict, resource_id: str, mode: str, count: int) -> dict:
        device = self.owned_device(resource_id, account)
        result = {"accepted": 0, "rejected": 0, "deliveries": 0}
        with self.lock("device", device["device_id"]):
            encrypted = (self.key_dir / f"{device['device_id']}.key").read_bytes()
            private = Ed25519PrivateKey.from_private_bytes(
                self.raw_cipher.decrypt(
                    encrypted[:12], encrypted[12:], device["device_id"].encode()
                )
            )
            for index in range(count):
                current = self.repo.one(
                    "SELECT last_sequence FROM devices WHERE device_id=?", (device["device_id"],)
                )
                packet = {
                    "schema_version": 2,
                    "resource_id": resource_id,
                    "device_id": device["device_id"],
                    "sequence": current["last_sequence"] + 1,
                    "issued_at": iso_now(),
                    "temp_c": 104.0 if mode == "anomaly" else 63.0 + index * 0.1,
                    "vibration_mm_s": 13.0 if mode == "anomaly" else 2.0,
                    "rpm": 2400 if mode == "anomaly" else 1500,
                }
                if mode == "replayed":
                    packet["sequence"] = current["last_sequence"]
                if mode == "stale":
                    packet["issued_at"] = (
                        (datetime.now(UTC) - timedelta(minutes=2))
                        .isoformat(timespec="milliseconds")
                        .replace("+00:00", "Z")
                    )
                if mode == "wrong-device":
                    packet["device_id"] = str(uuid4())
                packet["signature_b64"] = b64(private.sign(canonical(packet)))
                if mode == "tampered":
                    packet["temp_c"] = 99.0
                if mode == "malformed":
                    packet["unapproved_field"] = "synthetic"
                try:
                    result["deliveries"] += self.ingest(packet)
                    result["accepted"] += 1
                except GatewayError:
                    result["rejected"] += 1
        return result
