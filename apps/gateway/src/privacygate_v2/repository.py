"""Separate version-2 database. No legacy migration and no plaintext telemetry."""

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE accounts(account_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
 role TEXT NOT NULL CHECK(role IN ('owner','reader')), password_hash TEXT NOT NULL);
CREATE TABLE sessions(token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts,
 csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE login_attempts(bucket TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL);
CREATE TABLE devices(resource_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES accounts,
 device_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, ed25519_public_key_b64 TEXT NOT NULL,
 last_sequence INTEGER NOT NULL DEFAULT 0, registered INTEGER NOT NULL DEFAULT 0);
CREATE TABLE telemetry(id INTEGER PRIMARY KEY AUTOINCREMENT, resource_id TEXT NOT NULL REFERENCES devices,
 device_id TEXT NOT NULL, sequence INTEGER NOT NULL, accepted_at INTEGER NOT NULL,
 nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, UNIQUE(device_id,sequence));
CREATE TABLE reader_keys(account_id TEXT PRIMARY KEY REFERENCES accounts, key_id TEXT NOT NULL,
 key_version INTEGER NOT NULL, x25519_public_key_b64 TEXT NOT NULL);
CREATE TABLE policies(policy_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES accounts,
 resource_id TEXT NOT NULL REFERENCES devices, recipient_id TEXT NOT NULL REFERENCES accounts,
 expires_at INTEGER NOT NULL, policy_digest TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
 version INTEGER NOT NULL DEFAULT 0, receipt_json TEXT, created_at INTEGER NOT NULL);
CREATE TABLE outbox(transaction_id TEXT PRIMARY KEY, signer_id TEXT NOT NULL REFERENCES accounts,
 operation TEXT NOT NULL, entity_id TEXT NOT NULL, transaction_json TEXT NOT NULL,
 receipt_json TEXT, created_at INTEGER NOT NULL, request_digest TEXT NOT NULL);
CREATE TABLE deliveries(id INTEGER PRIMARY KEY AUTOINCREMENT, delivery_id TEXT NOT NULL UNIQUE,
 resource_id TEXT NOT NULL REFERENCES devices, recipient_id TEXT NOT NULL REFERENCES accounts,
 policy_digest TEXT NOT NULL, policy_version INTEGER NOT NULL, key_version INTEGER NOT NULL,
 created_at INTEGER NOT NULL, envelope_json TEXT NOT NULL);
CREATE INDEX deliveries_recipient ON deliveries(recipient_id,resource_id,id);
CREATE INDEX telemetry_resource ON telemetry(resource_id,id);
"""


class Repository:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if version == 0 and not tables:
                # executescript commits before execution: use individual DDL in our transaction.
                for statement in SCHEMA.split(";"):
                    if statement.strip():
                        db.execute(statement)
                db.execute("PRAGMA user_version=2")
            elif version != 2:
                raise RuntimeError("Unsupported gateway database version")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def one(self, sql: str, params=()):
        with self.connection() as db:
            row = db.execute(sql, params).fetchone()
            return dict(row) if row else None

    def all(self, sql: str, params=()):
        with self.connection() as db:
            return [dict(row) for row in db.execute(sql, params).fetchall()]

    def execute(self, sql: str, params=()):
        with self.connection() as db:
            db.execute(sql, params)

    def cleanup(self):
        now = int(time.time())
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            db.execute("DELETE FROM telemetry WHERE accepted_at<?", (now - 7 * 86400,))
            db.execute("DELETE FROM deliveries WHERE created_at<?", (now - 86400,))
            db.execute("DELETE FROM login_attempts WHERE window_start<?", (now - 3600,))

    def finalize(self, transaction_id: str, receipt: dict):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            operation = db.execute(
                "SELECT * FROM outbox WHERE transaction_id=?", (transaction_id,)
            ).fetchone()
            if not operation:
                raise RuntimeError("Unknown operation")
            if operation["receipt_json"] is not None:
                return
            encoded = json.dumps(receipt, sort_keys=True)
            db.execute(
                "UPDATE outbox SET receipt_json=? WHERE transaction_id=?", (encoded, transaction_id)
            )
            if operation["operation"] == "REGISTER_RESOURCE":
                db.execute(
                    "UPDATE devices SET registered=1 WHERE resource_id=?", (operation["entity_id"],)
                )
            else:
                status = "ACTIVE" if operation["operation"] == "GRANT" else "REVOKED"
                db.execute(
                    "UPDATE policies SET status=?,version=?,receipt_json=? WHERE policy_id=?",
                    (status, receipt["version"], encoded, operation["entity_id"]),
                )
                policy = db.execute(
                    "SELECT * FROM policies WHERE policy_id=?", (operation["entity_id"],)
                ).fetchone()
                db.execute(
                    "DELETE FROM deliveries WHERE resource_id=? AND recipient_id=?",
                    (policy["resource_id"], policy["recipient_id"]),
                )
