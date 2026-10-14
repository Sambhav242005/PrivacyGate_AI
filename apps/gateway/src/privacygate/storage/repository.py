"""Minimal sqlite3 repository: devices + policy drafts (stdlib only)."""
from __future__ import annotations

import base64
import binascii
import re
import sqlite3
import time
import uuid

from .models import SCHEMA

WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# PG-030/PG-031 key + delivery extensions (added without touching models.py).
KEY_DDL = """
CREATE TABLE IF NOT EXISTS wallet_keys (
  wallet_address TEXT PRIMARY KEY,
  key_id TEXT NOT NULL,
  x25519_public_key BLOB NOT NULL CHECK(length(x25519_public_key)=32),
  created_at TEXT NOT NULL,
  rotated_at TEXT NULL
);
CREATE TABLE IF NOT EXISTS key_epochs (
  resource_id TEXT NOT NULL,
  recipient_wallet TEXT NOT NULL,
  epoch INTEGER NOT NULL DEFAULT 0 CHECK(epoch>=0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (resource_id, recipient_wallet)
);
CREATE TABLE IF NOT EXISTS deliveries (
  delivery_id TEXT PRIMARY KEY,
  recipient_wallet TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  key_epoch INTEGER NOT NULL CHECK(key_epoch>=0),
  created_at TEXT NOT NULL,
  invalidated_at TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_recipient
  ON deliveries(recipient_wallet, created_at);
"""

_NOW_FMT = "%Y-%m-%dT%H:%M:%S.000Z"


def _now_utc() -> str:
    return time.strftime(_NOW_FMT, time.gmtime())


class Repository:
    def __init__(self, path: str = ":memory:"):
        # check_same_thread=False: FastAPI serves endpoints from a worker
        # threadpool, so the startup-thread connection must be shareable.
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.executescript(KEY_DDL)

    def enroll_device(self, resource_id: str, device_id: str, name: str,
                      ed25519_public_key_b64: str, owner_wallet: str = "") -> dict:
        _ = (name, owner_wallet)  # stored in later milestone; keep signature stable
        pub = base64.b64decode(ed25519_public_key_b64, validate=True)
        if len(pub) != 32:
            raise ValueError("ed25519 key must be 32 bytes")
        try:
            self.conn.execute(
                "INSERT INTO devices(device_id,resource_id,ed25519_public_key)"
                " VALUES(?,?,?)", (device_id, resource_id, pub))
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            raise ValueError(f"device exists: {e}") from e
        return {"device_id": device_id, "resource_id": resource_id, "status": "ACTIVE"}

    def get_device(self, device_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT device_id,resource_id,ed25519_public_key,last_sequence,active"
            " FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if not row:
            return None
        return {"device_id": row[0], "resource_id": row[1],
                "ed25519_public_key_b64": base64.b64encode(row[2]).decode(),
                "last_sequence": row[3], "active": bool(row[4])}

    def get_last_seq(self, device_id: str) -> int | None:
        row = self.conn.execute(
            "SELECT last_sequence FROM devices WHERE device_id=?",
            (device_id,)).fetchone()
        return None if row is None else int(row[0])

    def save_reading(self, device_id: str, sequence: int, issued_at: str,
                     nonce: bytes, ciphertext: bytes) -> dict:
        """Atomically advance last_sequence and store ciphertext.

        Raises KeyError (unknown device) or ValueError (replay). Ciphertext only.
        """
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        record_id = str(uuid.uuid4())
        now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        with self.conn:  # single tx: guard + seq bump + insert commit together
            row = self.conn.execute(
                "SELECT last_sequence FROM devices WHERE device_id=?",
                (device_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown device: {device_id}")
            if int(sequence) <= int(row[0]):
                raise ValueError(f"replay: seq {sequence} <= last {row[0]}")
            cur = self.conn.execute(
                "UPDATE devices SET last_sequence=? WHERE device_id=?"
                " AND last_sequence<?", (sequence, device_id, sequence))
            if cur.rowcount != 1:
                raise ValueError(f"replay: seq {sequence} lost race")
            try:
                self.conn.execute(
                    "INSERT INTO telemetry_records(record_id,device_id,sequence,"
                    "issued_at,nonce,encrypted_payload,created_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (record_id, device_id, sequence, issued_at,
                     bytes(nonce), bytes(ciphertext), now))
            except sqlite3.IntegrityError as e:
                raise ValueError(f"replay: duplicate record: {e}") from e
        return {"record_id": record_id, "device_id": device_id,
                "sequence": sequence}

    def get_reading(self, device_id: str, sequence: int) -> dict | None:
        row = self.conn.execute(
            "SELECT record_id,device_id,sequence,issued_at,nonce,"
            "encrypted_payload,created_at FROM telemetry_records"
            " WHERE device_id=? AND sequence=?", (device_id, sequence)).fetchone()
        if not row:
            return None
        return {"record_id": row[0], "device_id": row[1], "sequence": row[2],
                "issued_at": row[3], "nonce": bytes(row[4]),
                "ciphertext": bytes(row[5]), "created_at": row[6]}

    def list_readings(self, resource_id: str) -> list[dict]:
        """Ciphertext rows for one resource, stable order. No plaintext."""
        rows = self.conn.execute(
            "SELECT t.device_id,t.sequence,t.issued_at,t.nonce,"
            "t.encrypted_payload,d.resource_id FROM telemetry_records t"
            " JOIN devices d ON d.device_id=t.device_id"
            " WHERE d.resource_id=? ORDER BY t.device_id,t.sequence",
            (resource_id,)).fetchall()
        return [{"device_id": r[0], "sequence": int(r[1]), "issued_at": r[2],
                 "nonce": bytes(r[3]), "ciphertext": bytes(r[4]),
                 "resource_id": r[5]} for r in rows]

    def save_policy_draft(self, policy_json: str, policy_digest: str,
                          resource_id: str, owner_wallet: str,
                          recipient_wallet: str, revision: int,
                          expires_at_unix: int) -> dict:
        pid = str(uuid.uuid4())
        now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        self.conn.execute(
            "INSERT INTO policies(policy_id,resource_id,owner_wallet,recipient_wallet,"
            "policy_revision,policy_json,policy_digest,status,expires_at_unix,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (pid, resource_id, owner_wallet.lower(), recipient_wallet.lower(),
             revision, policy_json, policy_digest.lower(), "DRAFT",
             expires_at_unix, now))
        self.conn.commit()
        return {"policy_id": pid, "policy_revision": revision,
                "policy_digest": policy_digest, "status": "DRAFT"}

    def get_policy(self, policy_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT policy_id,policy_json,policy_digest,status FROM policies"
            " WHERE policy_id=?", (policy_id,)).fetchone()
        return None if not row else {"policy_id": row[0], "policy_json": row[1],
                                     "policy_digest": row[2], "status": row[3]}

    # -- PG-030 wallet-bound X25519 enrollment + key epochs (stdlib only) --

    @staticmethod
    def _normalize_wallet(wallet: str) -> str:
        if not isinstance(wallet, str) or not WALLET_RE.match(wallet):
            raise ValueError("invalid wallet address")
        return wallet.lower()

    def save_x25519_pubkey(self, wallet_address: str,
                           x25519_public_key_b64: str,
                           authenticated_wallet: str,
                           resource_id: str | None = None) -> dict:
        """Enroll caller's own X25519 key. Rotation bumps epoch + invalidates.

        Wallet-bound ownership: caller cannot write another wallet's key
        (raises PermissionError). A changed key sets ``rotated_at``, bumps
        the key epoch (for ``resource_id`` if given, else all pairs for this
        recipient) and marks unread deliveries invalidated. Same-key re-save
        is idempotent (no bump).
        """
        wallet = self._normalize_wallet(wallet_address)
        caller = self._normalize_wallet(authenticated_wallet)
        if wallet != caller:
            raise PermissionError("cannot enroll key for another wallet")
        try:
            pub = base64.b64decode(x25519_public_key_b64, validate=True)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"invalid public key: {e}") from e
        if len(pub) != 32:
            raise ValueError("x25519 public key must be 32 bytes")
        now = _now_utc()
        row = self.conn.execute(
            "SELECT x25519_public_key FROM wallet_keys WHERE wallet_address=?",
            (wallet,)).fetchone()
        if row is None:
            key_id = str(uuid.uuid4())
            self.conn.execute(
                "INSERT INTO wallet_keys(wallet_address,key_id,x25519_public_key,"
                "created_at) VALUES(?,?,?,?)", (wallet, key_id, pub, now))
            rotated = False
        elif bytes(row[0]) == pub:
            key_id = self.conn.execute(
                "SELECT key_id FROM wallet_keys WHERE wallet_address=?",
                (wallet,)).fetchone()[0]
            rotated = False
        else:
            key_id = str(uuid.uuid4())
            self.conn.execute(
                "UPDATE wallet_keys SET key_id=?,x25519_public_key=?,"
                "rotated_at=? WHERE wallet_address=?",
                (key_id, pub, now, wallet))
            rotated = True
        epoch: int | None = None
        if rotated:
            if resource_id is not None:
                epoch = self.bump_key_epoch(resource_id, wallet)
                self.invalidate_unread_deliveries(wallet, resource_id)
            else:
                pairs = self.conn.execute(
                    "SELECT resource_id FROM key_epochs"
                    " WHERE recipient_wallet=?", (wallet,)).fetchall()
                for (rid,) in pairs:
                    self.bump_key_epoch(rid, wallet)
                self.invalidate_unread_deliveries(wallet)
                epoch = None
        self.conn.commit()
        return {"wallet_address": wallet, "key_id": key_id,
                "registered_at": now, "rotated": rotated, "key_epoch": epoch}

    def get_x25519_pubkey(self, wallet_address: str) -> dict | None:
        wallet = self._normalize_wallet(wallet_address)
        row = self.conn.execute(
            "SELECT wallet_address,key_id,x25519_public_key,created_at,rotated_at"
            " FROM wallet_keys WHERE wallet_address=?", (wallet,)).fetchone()
        if not row:
            return None
        return {"wallet_address": row[0], "key_id": row[1],
                "x25519_public_key_b64": base64.b64encode(row[2]).decode(),
                "created_at": row[3], "rotated_at": row[4]}

    def get_key_epoch(self, resource_id: str, recipient_wallet: str) -> int:
        row = self.conn.execute(
            "SELECT epoch FROM key_epochs WHERE resource_id=? AND"
            " recipient_wallet=?", (resource_id, recipient_wallet.lower())
        ).fetchone()
        return 0 if not row else int(row[0])

    def bump_key_epoch(self, resource_id: str, recipient_wallet: str) -> int:
        recipient_wallet = self._normalize_wallet(recipient_wallet)
        now = _now_utc()
        row = self.conn.execute(
            "SELECT epoch FROM key_epochs WHERE resource_id=? AND"
            " recipient_wallet=?", (resource_id, recipient_wallet)).fetchone()
        epoch = 1 if not row else int(row[0]) + 1
        self.conn.execute(
            "INSERT INTO key_epochs(resource_id,recipient_wallet,epoch,updated_at)"
            " VALUES(?,?,?,?) ON CONFLICT(resource_id,recipient_wallet)"
            " DO UPDATE SET epoch=excluded.epoch,updated_at=excluded.updated_at",
            (resource_id, recipient_wallet, epoch, now))
        self.conn.commit()
        return epoch

    # -- PG-031 delivery queue metadata (ciphertext lives with caller) --

    def save_delivery(self, delivery_id: str, recipient_wallet: str,
                      resource_id: str, key_epoch: int) -> dict:
        recipient_wallet = self._normalize_wallet(recipient_wallet)
        if not isinstance(key_epoch, int) or key_epoch < 0:
            raise ValueError("invalid key_epoch")
        now = _now_utc()
        try:
            self.conn.execute(
                "INSERT INTO deliveries(delivery_id,recipient_wallet,resource_id,"
                "key_epoch,created_at) VALUES(?,?,?,?,?)",
                (delivery_id, recipient_wallet, resource_id, key_epoch, now))
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            raise ValueError(f"delivery exists: {e}") from e
        return {"delivery_id": delivery_id, "key_epoch": key_epoch}

    def get_delivery(self, delivery_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT delivery_id,recipient_wallet,resource_id,key_epoch,"
            "created_at,invalidated_at FROM deliveries WHERE delivery_id=?",
            (delivery_id,)).fetchone()
        return None if not row else {
            "delivery_id": row[0], "recipient_wallet": row[1],
            "resource_id": row[2], "key_epoch": row[3],
            "created_at": row[4], "invalidated_at": row[5]}

    def unread_deliveries(self, recipient_wallet: str,
                          resource_id: str | None = None) -> list[dict]:
        recipient_wallet = self._normalize_wallet(recipient_wallet)
        if resource_id is None:
            rows = self.conn.execute(
                "SELECT delivery_id,resource_id,key_epoch FROM deliveries"
                " WHERE recipient_wallet=? AND invalidated_at IS NULL",
                (recipient_wallet,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT delivery_id,resource_id,key_epoch FROM deliveries"
                " WHERE recipient_wallet=? AND resource_id=?"
                " AND invalidated_at IS NULL",
                (recipient_wallet, resource_id)).fetchall()
        return [{"delivery_id": r[0], "resource_id": r[1], "key_epoch": r[2]}
                for r in rows]

    def invalidate_unread_deliveries(
            self, recipient_wallet: str,
            resource_id: str | None = None) -> int:
        recipient_wallet = self._normalize_wallet(recipient_wallet)
        now = _now_utc()
        if resource_id is None:
            cur = self.conn.execute(
                "UPDATE deliveries SET invalidated_at=? WHERE recipient_wallet=?"
                " AND invalidated_at IS NULL", (now, recipient_wallet))
        else:
            cur = self.conn.execute(
                "UPDATE deliveries SET invalidated_at=? WHERE recipient_wallet=?"
                " AND resource_id=? AND invalidated_at IS NULL",
                (now, recipient_wallet, resource_id))
        self.conn.commit()
        return cur.rowcount
