"""PG-033 owner telemetry decrypt-on-read: owner gets decrypted rows,
non-owner 403, unauthenticated 401. Key loads from env (GATEWAY_DATA_KEY_B64)."""
import base64
import sys
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

GW_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(GW_SRC))

from privacygate.api.main import create_app  # noqa: E402
from privacygate.security.crypto_store import encrypt_reading, generate_data_key  # noqa: E402
from privacygate.storage.repository import Repository  # noqa: E402

OWNER = "0x" + "11" * 20
READER = "0x" + "22" * 20
RES = "0x" + "aa" * 32
DEVICE_ID = str(uuid.uuid4())
TS = "2026-10-14T00:00:00.000Z"


class FakeChain:
    def get_owner(self, resource_id):
        assert resource_id == RES
        return OWNER


def _seed(repo, key, n=3):
    repo.enroll_device(RES, DEVICE_ID, "comp-A",
                       base64.b64encode(b"\x01" * 32).decode())
    for i in range(1, n + 1):
        unsigned = {"schema_version": 1, "device_id": DEVICE_ID,
                    "resource_id": RES, "sequence": i, "issued_at": TS,
                    "telemetry": {"temp_c": 90.0 + i, "vibration_mm_s": 7.1,
                                  "rpm": 1450}}
        nonce, ct, _ = encrypt_reading(key, unsigned)
        repo.save_reading(DEVICE_ID, i, TS, nonce, ct)


def _app(monkeypatch, n=3):
    key = generate_data_key()
    monkeypatch.setenv("GATEWAY_DATA_KEY_B64",
                       base64.b64encode(key).decode())
    repo = Repository()
    _seed(repo, key, n)
    app = create_app(chain_client=FakeChain(), repository=repo)
    app.state.sessions["tok-owner"] = OWNER
    app.state.sessions["tok-reader"] = READER
    return app


def test_owner_reads_own_decrypted_rows(monkeypatch):
    c = TestClient(_app(monkeypatch), raise_server_exceptions=False)
    r = c.get(f"/v1/resources/{RES}/telemetry",
              cookies={"pg_session": "tok-owner"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["items"]) == 3
    assert body["next_cursor"] is None
    first = body["items"][0]
    assert first == {"device_id": DEVICE_ID, "sequence": 1,
                     "issued_at": TS, "temp_c": 91.0,
                     "vibration_mm_s": 7.1, "rpm": 1450}


def test_owner_pagination(monkeypatch):
    c = TestClient(_app(monkeypatch), raise_server_exceptions=False)
    r = c.get(f"/v1/resources/{RES}/telemetry?limit=2",
              cookies={"pg_session": "tok-owner"})
    assert r.status_code == 200, r.text
    assert len(r.json()["items"]) == 2
    assert r.json()["next_cursor"] == "2"
    r = c.get(f"/v1/resources/{RES}/telemetry?limit=2&cursor=2",
              cookies={"pg_session": "tok-owner"})
    assert r.status_code == 200, r.text
    assert len(r.json()["items"]) == 1
    assert r.json()["next_cursor"] is None


def test_non_owner_403_no_raw_fields(monkeypatch):
    c = TestClient(_app(monkeypatch), raise_server_exceptions=False)
    r = c.get(f"/v1/resources/{RES}/telemetry",
              cookies={"pg_session": "tok-reader"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "POLICY_DENIED"
    assert "91.0" not in r.text and "vibration" not in r.text


def test_unauthenticated_401(monkeypatch):
    c = TestClient(_app(monkeypatch), raise_server_exceptions=False)
    r = c.get(f"/v1/resources/{RES}/telemetry")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "NOT_AUTHENTICATED"
