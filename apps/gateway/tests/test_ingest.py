"""PG-012/PG-013 ingest + encrypted-storage tests."""
import base64
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from nacl.signing import SigningKey

GW_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(GW_SRC))

from privacygate.ingest.mqtt import ingest_message  # noqa: E402
from privacygate.security.crypto_store import (  # noqa: E402
    build_aad, decrypt, generate_data_key,
)

DEVICE_ID = str(uuid.uuid4())
RESOURCE_ID = "0x" + "aa" * 32
TEMP = 93.2


def _ts(now: float) -> str:
    return datetime.fromtimestamp(now, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")


def _signed(sk: SigningKey, seq: int, now: float, temp: float = TEMP,
            device_id: str = DEVICE_ID) -> dict:
    unsigned = {"schema_version": 1, "device_id": device_id,
                "resource_id": RESOURCE_ID, "sequence": seq,
                "issued_at": _ts(now),
                "telemetry": {"temp_c": temp, "vibration_mm_s": 7.1,
                              "rpm": 1450}}
    raw = json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode()
    sig = sk.sign(raw).signature
    return dict(unsigned,
                signature_b64=base64.b64encode(sig).decode())


@pytest.fixture()
def setup(tmp_path):
    from privacygate.storage.repository import Repository

    sk = SigningKey.generate()
    repo = Repository(str(tmp_path / "t.db"))
    repo.enroll_device(RESOURCE_ID, DEVICE_ID, "comp-A",
                       base64.b64encode(bytes(sk.verify_key)).decode())
    return sk, repo, generate_data_key(), time.time()


def _ingest(topic_device, msg, repo, key, now):
    topic = f"devices/{topic_device}/telemetry"
    return ingest_message(topic, json.dumps(msg).encode(), repo, key, now=now)


def test_valid_accept(setup):
    sk, repo, key, now = setup
    status, body = _ingest(DEVICE_ID, _signed(sk, 1, now), repo, key, now)
    assert status == 200 and body["sequence"] == 1
    assert repo.get_last_seq(DEVICE_ID) == 1


def test_tampered_sig_401(setup):
    sk, repo, key, now = setup
    msg = _signed(sk, 1, now)
    msg["telemetry"]["temp_c"] = 150.0  # tamper after signing
    status, body = _ingest(DEVICE_ID, msg, repo, key, now)
    assert status == 401
    assert body["error"]["code"] == "NOT_AUTHENTICATED"


def test_replay_409(setup):
    sk, repo, key, now = setup
    assert _ingest(DEVICE_ID, _signed(sk, 1, now), repo, key, now)[0] == 200
    # same seq, freshly signed so sig valid -> replay
    status, body = _ingest(DEVICE_ID, _signed(sk, 1, now), repo, key, now)
    assert status == 409
    assert body["error"]["code"] == "REPLAY_DETECTED"


def test_wrong_topic_rejected(setup):
    sk, repo, key, now = setup
    status, _ = _ingest(str(uuid.uuid4()), _signed(sk, 1, now),
                        repo, key, now)
    assert status == 400


def test_expired_rejected(setup):
    sk, repo, key, now = setup
    msg = _signed(sk, 1, now - 1000)  # outside ±300s window
    status, _ = _ingest(DEVICE_ID, msg, repo, key, now)
    assert status == 400


def test_sqlite_has_no_plaintext_temp(setup):
    sk, repo, key, now = setup
    assert _ingest(DEVICE_ID, _signed(sk, 1, now), repo, key, now)[0] == 200
    row = repo.get_reading(DEVICE_ID, 1)
    assert row is not None and len(row["nonce"]) == 12
    blob = row["ciphertext"]
    assert isinstance(blob, bytes) and str(TEMP).encode() not in blob
    # full-table scan: no row leaks plaintext temp or rpm
    rows = repo.conn.execute(
        "SELECT nonce, encrypted_payload FROM telemetry_records").fetchall()
    dump = b"".join(bytes(n) + bytes(c) for n, c in rows)
    assert str(TEMP).encode() not in dump and b"1450" not in dump
    # owner-path decrypt round-trips
    aad = build_aad(DEVICE_ID, 1, RESOURCE_ID)
    plain = json.loads(decrypt(key, row["nonce"], aad, blob).decode())
    assert plain["telemetry"]["temp_c"] == TEMP


def test_restart_persists_seq(setup, tmp_path):
    from privacygate.storage.repository import Repository

    sk, repo, key, now = setup
    assert _ingest(DEVICE_ID, _signed(sk, 2, now), repo, key, now)[0] == 200
    repo.conn.close()
    repo2 = Repository(str(tmp_path / "t.db"))
    try:
        assert repo2.get_last_seq(DEVICE_ID) == 2
    finally:
        repo2.conn.close()
