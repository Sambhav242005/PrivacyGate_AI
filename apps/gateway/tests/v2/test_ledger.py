"""Security and durability checks for the v2 local authorization ledger."""

from __future__ import annotations

import base64
import sqlite3
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GW_SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(GW_SRC))

from privacygate_v2 import Ledger, LedgerError, sign_transaction
from privacygate_v2 import ledger as ledger_module
from privacygate_v2.ledger import canonical_json


def _keypair() -> tuple[str, str, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
        private,
    )


@pytest.fixture
def actors():
    owner_id = str(uuid.uuid4())
    reader_id = str(uuid.uuid4())
    other_reader_id = str(uuid.uuid4())
    unknown_id = str(uuid.uuid4())
    owner_private, owner_public, _ = _keypair()
    reader_private, reader_public, _ = _keypair()
    other_private, other_public, _ = _keypair()
    unknown_private, _unknown_public, _ = _keypair()
    return {
        "owner_id": owner_id,
        "reader_id": reader_id,
        "other_reader_id": other_reader_id,
        "unknown_id": unknown_id,
        "owner_private": owner_private,
        "reader_private": reader_private,
        "other_private": other_private,
        "unknown_private": unknown_private,
        "identities": {
            owner_id: owner_public,
            reader_id: reader_public,
            other_reader_id: other_public,
        },
    }


def _make_ledger(path: Path, actors: dict[str, object]) -> Ledger:
    validator_private, _validator_public, _ = _keypair()
    # Preserve the key alongside the ledger config for tests that sign observations.
    actors["validator_private"] = validator_private
    return Ledger(path, validator_private, actors["identities"])


def _resource_id() -> str:
    return "0x" + uuid.uuid4().hex * 2


def _tx(
    actors: dict[str, object],
    signer: str = "owner",
    nonce: int = 1,
    operation: str = "REGISTER_RESOURCE",
    payload: dict[str, object] | None = None,
    **kwargs,
) -> dict[str, object]:
    signer_id = actors[f"{signer}_id"]
    private = actors[f"{signer}_private"]
    return sign_transaction(
        private,
        "privacygate-local-v2",
        signer_id,
        nonce,
        operation,
        payload if payload is not None else {"resource_id": _resource_id()},
        **kwargs,
    )


def test_register_grant_revoke_and_regrant_are_replayed_with_monotonic_versions(tmp_path, actors):
    ledger = _make_ledger(tmp_path / "ledger.sqlite3", actors)
    resource_id = _resource_id()

    register = _tx(actors, payload={"resource_id": resource_id})
    register_receipt = ledger.submit(register)
    assert set(register_receipt) == {
        "transaction_id",
        "block_height",
        "block_hash",
        "operation",
        "resource_id",
        "version",
    }
    assert register_receipt["version"] == 1
    assert ledger.next_nonce(actors["owner_id"]) == 2

    initial = ledger.state(resource_id, actors["reader_id"], "initial-challenge")
    assert initial["owner_id"] == actors["owner_id"]
    assert initial["grant"] is None
    body = {key: value for key, value in initial.items() if key != "signature_b64"}
    Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(actors["validator_private"])
    ).public_key().verify(base64.b64decode(initial["signature_b64"]), canonical_json(body))

    future = int(time.time()) + 3600
    grant = _tx(
        actors,
        nonce=2,
        operation="GRANT",
        payload={
            "resource_id": resource_id,
            "recipient_id": actors["reader_id"],
            "policy_digest": "a" * 64,
            "expires_at": future,
            "scope": "READ_INSIGHT",
        },
    )
    assert ledger.submit(grant)["version"] == 1
    active = ledger.state(resource_id, actors["reader_id"], "active-challenge")["grant"]
    assert active["active"] is True
    assert active["version"] == 1

    revoke = _tx(
        actors,
        nonce=3,
        operation="REVOKE",
        payload={"resource_id": resource_id, "recipient_id": actors["reader_id"]},
    )
    assert ledger.submit(revoke)["version"] == 2
    revoked = ledger.state(resource_id, actors["reader_id"], "revoked-challenge")["grant"]
    assert revoked["active"] is False
    assert revoked["version"] == 2

    regrant = _tx(
        actors,
        nonce=4,
        operation="GRANT",
        payload={
            "resource_id": resource_id,
            "recipient_id": actors["reader_id"],
            "policy_digest": "b" * 64,
            "expires_at": int(time.time()) + 3600,
            "scope": "READ_INSIGHT",
        },
    )
    assert ledger.submit(regrant)["version"] == 3
    assert (
        ledger.state(resource_id, actors["reader_id"], "regrant-challenge")["grant"]["version"] == 3
    )

    verification = ledger.verify()
    assert verification["valid"] is True
    assert verification["head_height"] == 4
    assert verification["transaction_count"] == 4
    assert ledger.next_nonce(actors["owner_id"]) == 5


def test_unregistered_resource_has_a_validator_signed_absence_observation(tmp_path, actors):
    ledger = _make_ledger(tmp_path / "ledger.sqlite3", actors)
    observation = ledger.state(_resource_id(), actors["reader_id"], "absent-resource-challenge")

    assert observation["owner_id"] is None
    assert observation["grant"] is None
    assert observation["head_height"] == 0
    body = {key: value for key, value in observation.items() if key != "signature_b64"}
    validator_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(actors["validator_private"])
    )
    validator_key.public_key().verify(
        base64.b64decode(observation["signature_b64"]), canonical_json(body)
    )


def test_exact_committed_retry_precedes_clock_and_nonce_checks(tmp_path, actors, monkeypatch):
    ledger = _make_ledger(tmp_path / "ledger.sqlite3", actors)
    tx = _tx(actors)
    first_receipt = ledger.submit(tx)

    future = tx["issued_at"] + 1000
    monkeypatch.setattr(ledger_module.time, "time", lambda: future)
    assert ledger.submit(tx) == first_receipt

    changed = dict(tx)
    changed["nonce"] = tx["nonce"] + 1
    with pytest.raises(LedgerError) as error:
        ledger.submit(changed)
    assert error.value.code == "TRANSACTION_ID_CONFLICT"


def test_rejects_stale_wrong_signer_tampered_signature_and_owner_change(tmp_path, actors):
    ledger = _make_ledger(tmp_path / "ledger.sqlite3", actors)
    now = int(time.time())
    stale = _tx(actors, issued_at=now - 31)
    with pytest.raises(LedgerError) as error:
        ledger.submit(stale)
    assert error.value.code == "TRANSACTION_EXPIRED"

    resource_id = _resource_id()
    unprovisioned = sign_transaction(
        actors["unknown_private"],
        ledger.chain_id,
        actors["unknown_id"],
        1,
        "REGISTER_RESOURCE",
        {"resource_id": resource_id},
    )
    with pytest.raises(LedgerError) as error:
        ledger.submit(unprovisioned)
    assert error.value.code == "IDENTITY_NOT_PROVISIONED"

    tampered = _tx(actors, payload={"resource_id": resource_id})
    tampered["payload"] = {"resource_id": "0x" + "c" * 64}
    with pytest.raises(LedgerError) as error:
        ledger.submit(tampered)
    assert error.value.code == "INVALID_SIGNATURE"

    good_register = _tx(actors, payload={"resource_id": resource_id})
    ledger.submit(good_register)
    other_owner = _tx(
        actors,
        signer="reader",
        payload={"resource_id": resource_id},
    )
    with pytest.raises(LedgerError) as error:
        ledger.submit(other_owner)
    assert error.value.code == "RESOURCE_ALREADY_REGISTERED"


def test_rejects_extra_fields_wrong_scope_expired_grant_and_non_owner_grant(tmp_path, actors):
    ledger = _make_ledger(tmp_path / "ledger.sqlite3", actors)
    resource_id = _resource_id()
    ledger.submit(_tx(actors, payload={"resource_id": resource_id}))

    with pytest.raises(LedgerError) as error:
        sign_transaction(
            actors["owner_private"],
            ledger.chain_id,
            actors["owner_id"],
            2,
            "GRANT",
            {
                "resource_id": resource_id,
                "recipient_id": actors["reader_id"],
                "policy_digest": "0" * 64,
                "expires_at": int(time.time()) + 60,
                "scope": "READ_RAW",
            },
        )
    assert error.value.code == "INVALID_SCOPE"

    extra = _tx(actors, nonce=2)
    extra["private_field"] = "sensor reading"
    with pytest.raises(LedgerError) as error:
        ledger.submit(extra)
    assert error.value.code == "INVALID_TRANSACTION"

    expired = _tx(
        actors,
        nonce=2,
        operation="GRANT",
        payload={
            "resource_id": resource_id,
            "recipient_id": actors["reader_id"],
            "policy_digest": "0" * 64,
            "expires_at": int(time.time()),
            "scope": "READ_INSIGHT",
        },
    )
    with pytest.raises(LedgerError) as error:
        ledger.submit(expired)
    assert error.value.code == "GRANT_EXPIRED"

    non_owner_grant = _tx(
        actors,
        signer="reader",
        operation="GRANT",
        payload={
            "resource_id": resource_id,
            "recipient_id": actors["other_reader_id"],
            "policy_digest": "d" * 64,
            "expires_at": int(time.time()) + 3600,
            "scope": "READ_INSIGHT",
        },
    )
    with pytest.raises(LedgerError) as error:
        ledger.submit(non_owner_grant)
    assert error.value.code == "OWNER_REQUIRED"


def test_nonce_serialization_allows_only_one_concurrent_submission(tmp_path, actors):
    ledger = _make_ledger(tmp_path / "ledger.sqlite3", actors)
    transactions = [
        _tx(actors, payload={"resource_id": _resource_id()}),
        _tx(actors, payload={"resource_id": _resource_id()}),
    ]

    def submit(tx):
        try:
            return ledger.submit(tx)
        except LedgerError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, transactions))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert results.count("NONCE_MISMATCH") == 1
    assert ledger.verify()["head_height"] == 1
    assert ledger.next_nonce(actors["owner_id"]) == 2


def test_precommit_rollback_and_lost_postcommit_response_survive_restart(
    tmp_path, actors, monkeypatch
):
    db_path = tmp_path / "ledger.sqlite3"
    ledger = _make_ledger(db_path, actors)
    tx = _tx(actors)

    def fail_before_commit():
        raise RuntimeError("simulated precommit crash")

    monkeypatch.setattr(ledger, "_before_commit", fail_before_commit)
    with pytest.raises(LedgerError) as error:
        ledger.submit(tx)
    assert error.value.code == "LEDGER_COMMIT_FAILED"
    assert ledger.receipt(tx["transaction_id"]) is None
    assert ledger.verify()["head_height"] == 0
    assert ledger.next_nonce(actors["owner_id"]) == 1

    monkeypatch.setattr(ledger, "_before_commit", lambda: None)

    def fail_after_commit():
        raise RuntimeError("simulated lost response")

    monkeypatch.setattr(ledger, "_after_commit", fail_after_commit)
    with pytest.raises(LedgerError) as error:
        ledger.submit(tx)
    assert error.value.code == "LEDGER_COMMIT_FAILED"
    committed = ledger.receipt(tx["transaction_id"])
    assert committed is not None

    # A caller can recover the durable receipt after restart, even after freshness expires.
    monkeypatch.setattr(ledger_module.time, "time", lambda: tx["issued_at"] + 1000)
    restarted = Ledger(db_path, actors["validator_private"], actors["identities"])
    assert restarted.submit(tx) == committed
    assert restarted.verify()["head_height"] == 1


def test_corruption_of_materialized_state_or_truncated_history_fails_closed(tmp_path, actors):
    db_path = tmp_path / "ledger.sqlite3"
    ledger = _make_ledger(db_path, actors)
    resource_id = _resource_id()
    ledger.submit(_tx(actors, payload={"resource_id": resource_id}))
    ledger.submit(
        _tx(
            actors,
            nonce=2,
            operation="GRANT",
            payload={
                "resource_id": resource_id,
                "recipient_id": actors["reader_id"],
                "policy_digest": "e" * 64,
                "expires_at": int(time.time()) + 3600,
                "scope": "READ_INSIGHT",
            },
        )
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE resources SET owner_id = ? WHERE resource_id = ?",
            (actors["reader_id"], resource_id),
        )
    with pytest.raises(LedgerError) as error:
        ledger.verify()
    assert error.value.code == "LEDGER_CORRUPT"
    with pytest.raises(LedgerError) as error:
        Ledger(db_path, actors["validator_private"], actors["identities"])
    assert error.value.code == "LEDGER_CORRUPT"

    # Independently show that deleting a block without repairing the indexes/head is detected.
    second_path = tmp_path / "truncated.sqlite3"
    second = Ledger(second_path, actors["validator_private"], actors["identities"])
    second.submit(_tx(actors, payload={"resource_id": _resource_id()}))
    with sqlite3.connect(second_path) as conn:
        conn.execute("DELETE FROM blocks WHERE height = 1")
    with pytest.raises(LedgerError) as error:
        Ledger(second_path, actors["validator_private"], actors["identities"])
    assert error.value.code == "LEDGER_CORRUPT"


def test_changed_pinned_identity_or_unknown_db_version_is_not_reset(tmp_path, actors):
    db_path = tmp_path / "ledger.sqlite3"
    _make_ledger(db_path, actors)
    _other_private, other_public, _ = _keypair()
    changed = dict(actors["identities"])
    changed[actors["reader_id"]] = other_public
    with pytest.raises(LedgerError) as error:
        Ledger(db_path, actors["validator_private"], changed)
    assert error.value.code == "CHAIN_CONFIG_MISMATCH"

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA user_version = 999")
    with pytest.raises(LedgerError) as error:
        Ledger(db_path, actors["validator_private"], actors["identities"])
    assert error.value.code == "LEDGER_SCHEMA_UNSUPPORTED"
    assert Path(db_path).exists()


def test_clock_regression_blocks_state_until_time_catches_up(tmp_path, actors, monkeypatch):
    ledger = _make_ledger(tmp_path / "ledger.sqlite3", actors)
    resource_id = _resource_id()
    ledger.submit(_tx(actors, payload={"resource_id": resource_id}))
    now = int(time.time())
    monkeypatch.setattr(ledger_module.time, "time", lambda: now)
    ledger.state(resource_id, actors["reader_id"], "checkpoint")

    monkeypatch.setattr(ledger_module.time, "time", lambda: now - 1)
    with pytest.raises(LedgerError) as error:
        ledger.state(resource_id, actors["reader_id"], "regressed")
    assert error.value.code == "CLOCK_REGRESSION"

    monkeypatch.setattr(ledger_module.time, "time", lambda: now)
    assert ledger.state(resource_id, actors["reader_id"], "caught-up")["observed_at"] == now
