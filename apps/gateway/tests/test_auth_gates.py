"""PG-043 A1/A2/A7 auth gates: no header spoof, sync ownership, key binding."""
import base64
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

GW_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(GW_SRC))

from privacygate.api.main import create_app  # noqa: E402

OWNER = "0x" + "11" * 20
READER = "0x" + "22" * 20
ATTACKER = "0x" + "33" * 20
RES = "0x" + "aa" * 32
CONTRACT = "0x" + "00" * 20
TX = "0x" + "ff" * 32
KEY_A = base64.b64encode(b"\x07" * 32).decode()


class FakeChain:
    def __init__(self, owner=OWNER):
        self.owner = owner
        self.digest = "0x" + "ab" * 32

    def get_owner(self, resource_id):
        assert resource_id == RES
        return self.owner

    def get_grant(self, resource_id, reader_wallet):
        return {"policy_digest": self.digest, "expires_at": 9999999999,
                "version": 1, "active": True, "scope": 1}

    def get_receipt(self, tx_hash):
        return {"status": 1, "block_number": 8, "to": CONTRACT,
                "tx_hash": tx_hash.lower()}

    def current_block(self):
        return 8

    def check_chain_id(self, expected):
        assert expected == 31337


def _app():
    chain = FakeChain()
    app = create_app(chain_client=chain,
                     chain_config={"contract_address": CONTRACT,
                                   "chain_id": 31337})
    app.state.sessions["tok-owner"] = OWNER
    app.state.sessions["tok-reader"] = READER
    app.state.sessions["tok-attacker"] = ATTACKER
    return app, chain


def _policy_body():
    return {"resource_id": RES, "recipient_wallet": READER,
            "scope": "READ_INSIGHT",
            "allowed_event_types": ["MACHINE_ANOMALY"],
            "allowed_fields": ["event_id", "event_type", "severity",
                               "observed_at", "model_version"],
            "expires_at_unix": int(time.time()) + 3600}


def test_spoofed_header_without_session_is_401():
    app, _ = _app()
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/v1/me", headers={"X-Wallet-Address": OWNER})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "NOT_AUTHENTICATED"
    # header mismatching the session wallet is also rejected
    r = c.get("/v1/me", cookies={"pg_session": "tok-owner"},
              headers={"X-Wallet-Address": ATTACKER})
    assert r.status_code == 401
    # session cookie alone authenticates
    r = c.get("/v1/me", cookies={"pg_session": "tok-owner"})
    assert r.status_code == 200
    assert r.json()["wallet_address"] == OWNER


def test_sync_without_ownership_is_403():
    app, chain = _app()
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/v1/policies", json=_policy_body(),
               cookies={"pg_session": "tok-owner"})
    assert r.status_code == 201, r.text
    pid = r.json()["policy_id"]
    chain.digest = r.json()["policy_digest"]
    r = c.post(f"/v1/policies/{pid}/sync", json={"transaction_hash": TX},
               cookies={"pg_session": "tok-attacker"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "POLICY_DENIED"


def test_key_overwrite_by_other_wallet_is_403():
    app, _ = _app()
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/v1/keys", json={"x25519_public_key_b64": KEY_A},
               cookies={"pg_session": "tok-owner"})
    assert r.status_code == 200, r.text
    other_key = base64.b64encode(b"\x09" * 32).decode()
    r = c.post("/v1/keys", json={"x25519_public_key_b64": other_key,
                                 "wallet_address": OWNER},
               cookies={"pg_session": "tok-reader"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "POLICY_DENIED"
    kept = app.state.queue.keys[OWNER]["x25519_public_key_b64"]
    assert kept == KEY_A  # attacker's key write did not overwrite owner's
