"""Minimal SQLite DDL for PG-010/PG-023 stubs."""
DEVICES_DDL = """
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL,
  ed25519_public_key BLOB NOT NULL CHECK(length(ed25519_public_key)=32),
  last_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_sequence>=0),
  active INTEGER NOT NULL DEFAULT 1
);
"""

POLICIES_DDL = """
CREATE TABLE IF NOT EXISTS policies (
  policy_id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL,
  owner_wallet TEXT NOT NULL,
  recipient_wallet TEXT NOT NULL,
  policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
  policy_json TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'DRAFT',
  contract_version INTEGER NULL,
  confirmed_block INTEGER NULL,
  expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix>0),
  created_at TEXT NOT NULL
);
"""

TELEMETRY_DDL = """
CREATE TABLE IF NOT EXISTS telemetry_records (
  record_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  sequence INTEGER NOT NULL CHECK(sequence>0),
  issued_at TEXT NOT NULL,
  nonce BLOB NOT NULL CHECK(length(nonce)=12),
  encrypted_payload BLOB NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(device_id,sequence)
);
CREATE INDEX IF NOT EXISTS idx_telemetry_device_seq
  ON telemetry_records(device_id,sequence);
"""

SCHEMA = DEVICES_DDL + POLICIES_DDL + TELEMETRY_DDL

