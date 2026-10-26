"""Gateway security checks use the real signed ledger and its validating HTTP client."""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi.testclient import TestClient
from privacygate_v2.api import create_app
from privacygate_v2.ledger import Ledger
from privacygate_v2.ledger import create_app as validator_app
from privacygate_v2.ledger_client import LedgerClient
from privacygate_v2.model import evaluate_model
from privacygate_v2.repository import Repository
from privacygate_v2.security import b64, canonical, unb64

ORIGIN = {"Origin": "http://127.0.0.1:3000"}


@pytest.fixture
def runtime(tmp_path):
    private = [Ed25519PrivateKey.generate() for _ in range(4)]
    ids = [str(uuid4()) for _ in range(3)]
    identities = {
        identity: b64(key.public_key().public_bytes_raw()) for identity, key in zip(ids, private)
    }
    ledger = Ledger(tmp_path / "ledger.db", b64(private[3].private_bytes_raw()), identities)
    config = {
        "runtime_root": str(tmp_path),
        "raw_key_b64": b64(os.urandom(32)),
        "owner_private_keys": {ids[0]: b64(private[0].private_bytes_raw())},
        "chain": {**ledger.public_config(), "url": "http://validator"},
        "accounts": [
            {
                "account_id": identity,
                "username": f"user{i}",
                "role": "owner" if i == 0 else "reader",
                "password": "test-password-2401",
            }
            for i, identity in enumerate(ids)
        ],
    }
    chain = LedgerClient("http://validator", config["chain"], tmp_path / "checkpoint.json")
    chain._http.close()
    chain._http = TestClient(validator_app(ledger))
    app = create_app(config, chain)
    clients = [TestClient(app, headers=ORIGIN) for _ in ids]
    for i, client in enumerate(clients):
        response = client.post(
            "/v2/auth/login", json={"username": f"user{i}", "password": "test-password-2401"}
        )
        assert response.status_code == 200, response.text
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    yield app, config, clients, ids, ledger
    for client in clients:
        client.close()
    chain.close()


def device(owner):
    response = owner.post("/v2/devices", json={"name": "Synthetic compressor"})
    assert response.status_code == 200, response.text
    return response.json()["resource_id"]


def grant(owner, resource_id, recipient_id):
    response = owner.post(
        "/v2/policies",
        json={
            "resource_id": resource_id,
            "recipient_id": recipient_id,
            "expires_at": int(time.time()) + 3600,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def enroll(reader):
    key = X25519PrivateKey.generate()
    response = reader.post(
        "/v2/keys",
        json={"x25519_public_key_b64": b64(key.public_key().public_bytes_raw()), "replace": False},
    )
    assert response.status_code == 200, response.text
    return key


def decrypt(envelope, private):
    aad = unb64(envelope["aad_b64"])
    context = json.loads(aad)
    assert canonical(context) == aad
    for key, value in context.items():
        if key != "event_id":
            assert envelope[key] == value
    info = {
        k: context[k]
        for k in (
            "event_id",
            "key_epoch",
            "key_version",
            "policy_version",
            "recipient_id",
            "resource_id",
        )
    }
    shared = private.exchange(
        X25519PublicKey.from_public_bytes(unb64(envelope["ephemeral_public_key_b64"], 32))
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(32),
        info=b"privacygate-envelope-v2|" + canonical(info),
    ).derive(shared)
    return json.loads(
        AESGCM(key).decrypt(unb64(envelope["nonce_b64"]), unb64(envelope["ciphertext_b64"]), aad)
    )


def test_real_ledger_signed_ingest_encryption_revocation(runtime):
    app, _config, (owner, reader, other), ids, ledger = runtime
    resource = device(owner)
    private = enroll(reader)
    other_private = enroll(other)
    first = grant(owner, resource, ids[1])
    grant(owner, resource, ids[2])
    result = owner.post(
        "/v2/simulator", json={"resource_id": resource, "mode": "anomaly", "count": 2}
    )
    assert result.json() == {"accepted": 2, "rejected": 0, "deliveries": 4}, result.text
    envelopes = reader.get("/v2/insights", params={"resource_id": resource, "limit": 1}).json()
    assert envelopes["next_cursor"]
    envelope = envelopes["items"][0]
    plain = decrypt(envelope, private)
    assert set(plain) == {"event_id", "event_type", "severity", "observed_at", "model_version"}
    with pytest.raises(InvalidTag):
        decrypt(envelope, other_private)
    for mode in ("tampered", "replayed", "stale", "malformed", "wrong-device"):
        response = owner.post(
            "/v2/simulator", json={"resource_id": resource, "mode": mode, "count": 2}
        )
        assert response.json() == {"accepted": 0, "rejected": 2, "deliveries": 0}
    assert reader.get(f"/v2/resources/{resource}/telemetry").status_code == 403
    assert len(owner.get(f"/v2/resources/{resource}/telemetry").json()["items"]) == 2
    revoke = owner.post(f"/v2/policies/{first['policy_id']}/revoke", json={})
    assert revoke.status_code == 200, revoke.text
    assert reader.get("/v2/insights", params={"resource_id": resource}).status_code == 403
    assert other.get("/v2/insights", params={"resource_id": resource}).status_code == 200
    regranted = grant(owner, resource, ids[1])
    assert regranted["version"] > first["version"]
    assert reader.get("/v2/insights", params={"resource_id": resource}).json()["items"] == []
    # Inspect every DB page, including WAL: field names and plaintext insights never persist.
    for path in app.state.gateway.repo.path.parent.glob("gateway.db*"):
        raw = path.read_bytes()
        assert b"temp_c" not in raw and b"MACHINE_ANOMALY" not in raw
    assert ledger.verify()["valid"] is True


def test_auth_origin_csrf_strict_bodies_sessions_restart(runtime):
    app, config, (owner, reader, _other), ids, _ = runtime
    csrf = owner.get("/v2/me").json()["csrf_token"]
    assert owner.get("/v2/me").json()["csrf_token"] == csrf
    assert (
        owner.post(
            "/v2/devices", json={"name": "x"}, headers={"Origin": "http://evil.test"}
        ).status_code
        == 403
    )
    assert (
        owner.post("/v2/devices", json={"name": "x"}, headers={"X-CSRF-Token": "wrong"}).status_code
        == 403
    )
    assert owner.post("/v2/devices", json={"name": "x", "owner_id": ids[1]}).status_code == 422
    assert reader.get("/v2/devices").status_code == 403
    assert reader.get("/v2/accounts").status_code == 403
    restarted = create_app(config, app.state.gateway.chain)
    client = TestClient(restarted, headers=ORIGIN, cookies=owner.cookies)
    assert client.get("/v2/me").json()["csrf_token"] == csrf
    response = owner.post("/v2/auth/logout", json={})
    assert response.json() == {"ok": True}
    assert client.get("/v2/me").status_code == 401
    row = app.state.gateway.repo.one("SELECT * FROM accounts WHERE account_id=?", (ids[0],))
    assert "test-password-2401" not in row["password_hash"]


def test_operation_retry_is_exact_and_conflicts(runtime):
    _app, _, (owner, _, _), _ids, _ledger = runtime
    operation_id = str(uuid4())
    headers = {"X-Operation-ID": operation_id}
    first = owner.post("/v2/devices", json={"name": "retry"}, headers=headers)
    second = owner.post("/v2/devices", json={"name": "retry"}, headers=headers)
    assert first.status_code == second.status_code == 200, first.text
    assert first.json() == second.json()
    assert owner.post("/v2/devices", json={"name": "changed"}, headers=headers).status_code == 409
    assert first.json()["receipt"]["transaction_id"] == operation_id
    assert owner.get(f"/v2/operations/{operation_id}").json()["status"] == "COMMITTED"


def test_model_holdout_and_unknown_database(tmp_path):
    result = evaluate_model()
    assert result["holdout_count"] == 384
    assert result["results"]["isolation_forest"]["tp"] > 0
    import sqlite3

    connection = sqlite3.connect(tmp_path / "unknown.db")
    connection.execute("PRAGMA user_version=1")
    connection.close()
    with pytest.raises(RuntimeError):
        Repository(tmp_path / "unknown.db")


def test_outage_key_rotation_expiry_and_retention(runtime, monkeypatch):
    app, _config, (owner, reader, _other), ids, _ledger = runtime
    resource = device(owner)
    private = enroll(reader)
    policy = grant(owner, resource, ids[1])
    payload = {"resource_id": resource, "mode": "anomaly", "count": 1}
    assert owner.post("/v2/simulator", json=payload).json()["deliveries"] == 1
    key = X25519PrivateKey.generate()
    body = {"x25519_public_key_b64": b64(key.public_key().public_bytes_raw()), "replace": False}
    assert reader.post("/v2/keys", json=body).status_code == 409
    assert reader.post("/v2/keys", json={**body, "replace": True}).json()["key_version"] == 2
    assert reader.get("/v2/insights", params={"resource_id": resource}).json()["items"] == []
    assert owner.post("/v2/simulator", json=payload).json()["deliveries"] == 1
    envelope = reader.get("/v2/insights", params={"resource_id": resource}).json()["items"][0]
    assert decrypt(envelope, key)["event_type"] == "MACHINE_ANOMALY"
    with pytest.raises(InvalidTag):
        decrypt(envelope, private)
    actual_state = app.state.gateway.chain.state

    def unavailable(*args):
        raise OSError("unreachable synthetic validator")

    monkeypatch.setattr(app.state.gateway.chain, "state", unavailable)
    assert owner.post("/v2/simulator", json=payload).json() == {
        "accepted": 1,
        "rejected": 0,
        "deliveries": 0,
    }
    denied = reader.get("/v2/insights", params={"resource_id": resource})
    assert denied.status_code == 503
    assert "ciphertext_b64" not in denied.text
    monkeypatch.setattr(app.state.gateway.chain, "state", actual_state)
    # Even a cryptographically fresh observation cannot authorize an expired local policy.
    app.state.gateway.repo.execute(
        "UPDATE policies SET expires_at=? WHERE policy_id=?",
        (int(time.time()) - 1, policy["policy_id"]),
    )
    assert reader.get("/v2/insights", params={"resource_id": resource}).status_code == 403
    repo = app.state.gateway.repo
    repo.execute("UPDATE telemetry SET accepted_at=?", (int(time.time()) - 8 * 86400,))
    repo.execute("UPDATE deliveries SET created_at=?", (int(time.time()) - 2 * 86400,))
    repo.cleanup()
    assert not repo.all("SELECT id FROM telemetry") and not repo.all("SELECT id FROM deliveries")


def test_outbox_crash_before_and_after_commit_reconciles_exactly(runtime, monkeypatch):
    app, config, (owner, _, _), ids, ledger = runtime
    gateway = app.state.gateway
    actual_submit = gateway.chain.submit
    operation_id = str(uuid4())

    def lost_response(tx):
        actual_submit(tx)
        raise OSError("synthetic lost response")

    monkeypatch.setattr(gateway.chain, "submit", lost_response)
    response = owner.post(
        "/v2/devices", json={"name": "lost response"}, headers={"X-Operation-ID": operation_id}
    )
    assert response.status_code == 503
    pending = gateway.repo.one("SELECT * FROM outbox WHERE transaction_id=?", (operation_id,))
    assert pending["receipt_json"] is None
    committed_receipt = ledger.receipt(operation_id)
    assert committed_receipt is not None
    monkeypatch.setattr(gateway.chain, "submit", actual_submit)
    retry = owner.post(
        "/v2/devices", json={"name": "lost response"}, headers={"X-Operation-ID": operation_id}
    )
    assert retry.status_code == 200 and retry.json()["receipt"] == committed_receipt
    assert ledger.next_nonce(ids[0]) == 2
    # A crash before the chain commits still leaves an exact signed durable request.
    second_id = str(uuid4())

    def before_commit(tx):
        raise OSError("synthetic precommit crash")

    monkeypatch.setattr(gateway.chain, "submit", before_commit)
    assert (
        owner.post(
            "/v2/devices", json={"name": "before commit"}, headers={"X-Operation-ID": second_id}
        ).status_code
        == 503
    )
    assert ledger.receipt(second_id) is None
    monkeypatch.setattr(gateway.chain, "submit", actual_submit)
    restarted = create_app(config, gateway.chain)
    client = TestClient(
        restarted,
        headers={**ORIGIN, "X-CSRF-Token": owner.headers["X-CSRF-Token"]},
        cookies=owner.cookies,
    )
    assert client.get(f"/v2/operations/{second_id}").json()["status"] == "COMMITTED"
    assert ledger.next_nonce(ids[0]) == 3


def test_atomic_sequence_and_cookie_hashes(runtime):
    app, _config, (owner, reader, other), _ids, _ = runtime
    resource = device(owner)
    gateway = app.state.gateway
    enrolled = gateway.repo.one("SELECT * FROM devices WHERE resource_id=?", (resource,))
    encrypted = (gateway.key_dir / f"{enrolled['device_id']}.key").read_bytes()
    key = Ed25519PrivateKey.from_private_bytes(
        gateway.raw_cipher.decrypt(encrypted[:12], encrypted[12:], enrolled["device_id"].encode())
    )
    from privacygate_v2.schemas import iso_now

    packet = {
        "schema_version": 2,
        "resource_id": resource,
        "device_id": enrolled["device_id"],
        "sequence": 1,
        "issued_at": iso_now(),
        "temp_c": 63.0,
        "vibration_mm_s": 2.0,
        "rpm": 1500,
    }
    packet["signature_b64"] = b64(key.sign(canonical(packet)))

    def publish(_):
        from privacygate_v2.service import GatewayError

        try:
            gateway.ingest(packet)
            return True
        except GatewayError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(publish, range(8))) == 1
    assert len(gateway.repo.all("SELECT id FROM telemetry")) == 1
    for row in gateway.repo.all("SELECT token_hash FROM sessions"):
        assert row["token_hash"] not in {
            c.cookies.get("pg_v2_session") for c in (owner, reader, other)
        }


def test_authorization_exact_policy_components(runtime):
    import copy

    app, _config, (owner, reader, _other), ids, _ledger = runtime
    resource = device(owner)
    enroll(reader)
    grant(owner, resource, ids[1])
    gateway = app.state.gateway
    policy = gateway.repo.one("SELECT * FROM policies WHERE resource_id=?", (resource,))
    observation = gateway.chain.state(resource, ids[1])
    assert gateway.authorized(policy, observation)
    for field, invalid in (
        ("scope", "READ_DETAIL"),
        ("recipient_id", ids[2]),
        ("policy_digest", "0" * 64),
        ("version", 999),
        ("expires_at", int(time.time()) - 1),
        ("active", False),
    ):
        changed = copy.deepcopy(observation)
        changed["grant"][field] = invalid
        assert not gateway.authorized(policy, changed)
    for field, invalid in (
        ("owner_id", ids[2]),
        ("recipient_id", ids[2]),
        ("resource_id", "0x" + "f" * 64),
    ):
        changed = copy.deepcopy(observation)
        changed[field] = invalid
        assert not gateway.authorized(policy, changed)


def test_login_throttle_host_body_limits_and_sanitized_errors(runtime):
    app, _config, (owner, _, _), _ids, _ledger = runtime
    client = TestClient(app, headers=ORIGIN)
    marker = "synthetic-password-canary-123456"
    assert (
        client.post(
            "/v2/auth/login", json={"username": "no-such-user", "password": marker, "extra": marker}
        ).status_code
        == 422
    )
    for _ in range(10):
        response = client.post(
            "/v2/auth/login", json={"username": "no-such-user", "password": marker}
        )
        assert response.status_code == 401 and marker not in response.text
    assert (
        client.post(
            "/v2/auth/login", json={"username": "no-such-user", "password": marker}
        ).status_code
        == 429
    )
    assert client.get("/v2/health", headers={"Host": "evil.test"}).status_code == 400
    assert owner.post("/v2/devices", json={"name": "x" * 20000}).status_code == 413


def test_expired_uncommitted_registration_unblocks_next_operation(runtime, monkeypatch):
    app, _config, (owner, reader, _other), ids, ledger = runtime
    gateway = app.state.gateway
    actual_submit, actual_state = gateway.chain.submit, gateway.chain.state
    operation_id = str(uuid4())

    def unavailable(*_):
        raise OSError("synthetic validator outage")

    monkeypatch.setattr(gateway.chain, "submit", unavailable)
    assert (
        owner.post(
            "/v2/devices", json={"name": "expired draft"}, headers={"X-Operation-ID": operation_id}
        ).status_code
        == 503
    )
    original = gateway.repo.one("SELECT * FROM outbox WHERE transaction_id=?", (operation_id,))[
        "transaction_json"
    ]
    future = time.time() + 40
    monkeypatch.setattr(time, "time", lambda: future)
    monkeypatch.setattr(gateway.chain, "state", unavailable)
    assert owner.get(f"/v2/operations/{operation_id}").status_code == 503
    assert (
        gateway.repo.one("SELECT receipt_json FROM outbox WHERE transaction_id=?", (operation_id,))[
            "receipt_json"
        ]
        is None
    )
    monkeypatch.setattr(gateway.chain, "submit", actual_submit)
    monkeypatch.setattr(gateway.chain, "state", actual_state)
    expired = owner.get(f"/v2/operations/{operation_id}")
    assert expired.json() == {
        "transaction_id": operation_id,
        "status": "FAILED",
        "code": "OPERATION_EXPIRED",
        "receipt": None,
    }, expired.text
    assert reader.get(f"/v2/operations/{operation_id}").status_code == 403
    assert (
        gateway.repo.one(
            "SELECT transaction_json FROM outbox WHERE transaction_id=?", (operation_id,)
        )["transaction_json"]
        == original
    )
    assert (
        owner.post(
            "/v2/devices", json={"name": "expired draft"}, headers={"X-Operation-ID": operation_id}
        ).status_code
        == 409
    )
    assert owner.post("/v2/devices", json={"name": "new operation"}).status_code == 200
    assert ledger.next_nonce(ids[0]) == 2


def test_old_committed_receipt_recovers_before_expiration_check(runtime, monkeypatch):
    app, _config, (owner, _reader, _other), ids, ledger = runtime
    gateway = app.state.gateway
    actual_submit = gateway.chain.submit
    operation_id = str(uuid4())

    def lost_response(tx):
        actual_submit(tx)
        raise OSError("synthetic lost response")

    monkeypatch.setattr(gateway.chain, "submit", lost_response)
    assert (
        owner.post(
            "/v2/devices", json={"name": "committed old"}, headers={"X-Operation-ID": operation_id}
        ).status_code
        == 503
    )
    future = time.time() + 40
    monkeypatch.setattr(time, "time", lambda: future)
    recovered = owner.get(f"/v2/operations/{operation_id}")
    assert recovered.json()["status"] == "COMMITTED", recovered.text
    assert ledger.next_nonce(ids[0]) == 2


def test_expired_draft_policy_is_failed_and_audit_only_contains_receipts(runtime, monkeypatch):
    app, _config, (owner, _reader, _other), ids, ledger = runtime
    resource = device(owner)
    gateway = app.state.gateway
    actual_submit = gateway.chain.submit
    operation_id = str(uuid4())
    body = {"resource_id": resource, "recipient_id": ids[1], "expires_at": int(time.time()) + 3600}

    def before_commit(_):
        raise OSError("synthetic before commit")

    monkeypatch.setattr(gateway.chain, "submit", before_commit)
    assert (
        owner.post("/v2/policies", json=body, headers={"X-Operation-ID": operation_id}).status_code
        == 503
    )
    future = time.time() + 40
    monkeypatch.setattr(time, "time", lambda: future)
    monkeypatch.setattr(gateway.chain, "submit", actual_submit)
    assert owner.get(f"/v2/operations/{operation_id}").json()["status"] == "FAILED"
    policies = owner.get("/v2/policies", params={"resource_id": resource}).json()["items"]
    assert (
        len(policies) == 1 and policies[0]["status"] == "FAILED" and policies[0]["receipt"] is None
    )
    assert owner.post("/v2/policies", json=body).status_code == 200
    audit = owner.get("/v2/audit", params={"resource_id": resource}).json()["items"]
    assert len(audit) == 2 and all("block_hash" in r for r in audit)
    assert ledger.next_nonce(ids[0]) == 3
