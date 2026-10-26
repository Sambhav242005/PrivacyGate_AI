"""HTTP validator and fail-closed client verification tests."""

from __future__ import annotations

import base64
import json
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

GW_SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(GW_SRC))

from privacygate_v2 import Ledger, LedgerClient, LedgerError, create_app, sign_transaction
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
def stack(tmp_path):
    owner_id, reader_id = str(uuid.uuid4()), str(uuid.uuid4())
    owner_private, owner_public, _ = _keypair()
    _reader_private, reader_public, _ = _keypair()
    validator_private, _validator_public, validator_key = _keypair()
    ledger = Ledger(
        tmp_path / "ledger.sqlite3",
        validator_private,
        {owner_id: owner_public, reader_id: reader_public},
    )
    resource_id = "0x" + uuid.uuid4().hex * 2
    register = sign_transaction(
        owner_private,
        ledger.chain_id,
        owner_id,
        1,
        "REGISTER_RESOURCE",
        {"resource_id": resource_id},
    )
    return {
        "ledger": ledger,
        "owner_id": owner_id,
        "reader_id": reader_id,
        "owner_private": owner_private,
        "validator_private": validator_key,
        "resource_id": resource_id,
        "register": register,
    }


@contextmanager
def _client_for(ledger: Ledger, checkpoint_path: Path | None = None):
    with TestClient(create_app(ledger)) as server:
        client = LedgerClient("http://validator.local", ledger.config, checkpoint_path)
        client._http.close()

        def handle(request: httpx.Request) -> httpx.Response:
            response = server.request(
                request.method,
                request.url.path,
                params=request.url.params,
                content=request.content,
                headers={"content-type": request.headers.get("content-type", "application/json")},
            )
            return httpx.Response(
                status_code=response.status_code,
                headers=dict(response.headers),
                content=response.content,
                request=request,
            )

        client._http = httpx.Client(transport=httpx.MockTransport(handle))
        try:
            yield client
        finally:
            client.close()


def _signed_observation(stack, challenge: str, *, observed_at: int | None = None):
    ledger = stack["ledger"]
    body = ledger.state(stack["resource_id"], stack["reader_id"], challenge)
    body = {key: value for key, value in body.items() if key != "signature_b64"}
    if observed_at is not None:
        body["observed_at"] = observed_at
    signature = stack["validator_private"].sign(canonical_json(body))
    return {**body, "signature_b64": base64.b64encode(signature).decode("ascii")}


def test_validator_http_and_client_submit_receipt_nonce_and_fresh_state(stack, tmp_path):
    ledger = stack["ledger"]
    checkpoint_path = tmp_path / "gateway" / "ledger-head.json"
    with _client_for(ledger, checkpoint_path) as client:
        receipt = client.submit(stack["register"])
        assert receipt["block_height"] == 1
        assert client.receipt(receipt["transaction_id"]) == receipt
        assert client.next_nonce(stack["owner_id"]) == 2

        first = client.state(stack["resource_id"], stack["reader_id"])
        second = client.state(stack["resource_id"], stack["reader_id"])
        assert first["challenge"] != second["challenge"]
        assert first["grant"] is None
        assert first["head_height"] == 1

    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    assert checkpoint["head_height"] == 1
    assert checkpoint["head_hash"] == receipt["block_hash"]

    # A fresh process reuses the durable checkpoint and accepts the same signed head.
    with _client_for(ledger, checkpoint_path) as restarted_client:
        assert restarted_client.state(stack["resource_id"], stack["reader_id"])["head_height"] == 1


def test_client_accepts_signed_absence_and_rejects_tampered_owner_or_grant(stack):
    ledger = stack["ledger"]
    resource_id = stack["resource_id"]
    reader_id = stack["reader_id"]

    with _client_for(ledger) as client:
        observation = client.state(resource_id, reader_id)
        assert observation["owner_id"] is None
        assert observation["grant"] is None
        assert observation["head_height"] == 0

        def tampered_owner(request: httpx.Request) -> httpx.Response:
            challenge = json.loads(request.content)["challenge"]
            body = ledger.state(resource_id, reader_id, challenge)
            body["owner_id"] = str(uuid.uuid4())
            return httpx.Response(200, json=body, request=request)

        client._http.close()
        client._http = httpx.Client(transport=httpx.MockTransport(tampered_owner))
        with pytest.raises(LedgerError) as error:
            client.state(resource_id, reader_id)
        assert error.value.code == "INVALID_OBSERVATION_SIGNATURE"

        def impossible_grant(request: httpx.Request) -> httpx.Response:
            challenge = json.loads(request.content)["challenge"]
            body = ledger.state(resource_id, reader_id, challenge)
            body["grant"] = {
                "recipient_id": reader_id,
                "policy_digest": "0" * 64,
                "expires_at": int(time.time()) + 60,
                "scope": "READ_INSIGHT",
                "active": True,
                "version": 1,
            }
            return httpx.Response(200, json=body, request=request)

        client._http.close()
        client._http = httpx.Client(transport=httpx.MockTransport(impossible_grant))
        with pytest.raises(LedgerError) as error:
            client.state(resource_id, reader_id)
        assert error.value.code == "LEDGER_PROTOCOL_ERROR"


def test_client_rejects_stale_replayed_and_invalidly_signed_observations(stack):
    ledger = stack["ledger"]
    ledger.submit(stack["register"])

    with _client_for(ledger) as client:

        def stale_handler(request: httpx.Request) -> httpx.Response:
            challenge = json.loads(request.content)["challenge"]
            body = _signed_observation(stack, challenge, observed_at=int(time.time()) - 6)
            return httpx.Response(200, json=body, request=request)

        client._http.close()
        client._http = httpx.Client(transport=httpx.MockTransport(stale_handler))
        with pytest.raises(LedgerError) as error:
            client.state(stack["resource_id"], stack["reader_id"])
        assert error.value.code == "STALE_OBSERVATION"

        def replayed_handler(request: httpx.Request) -> httpx.Response:
            body = _signed_observation(stack, "a-different-old-challenge")
            return httpx.Response(200, json=body, request=request)

        client._http.close()
        client._http = httpx.Client(transport=httpx.MockTransport(replayed_handler))
        with pytest.raises(LedgerError) as error:
            client.state(stack["resource_id"], stack["reader_id"])
        assert error.value.code == "LEDGER_PROTOCOL_ERROR"

        def invalid_signature_handler(request: httpx.Request) -> httpx.Response:
            challenge = json.loads(request.content)["challenge"]
            body = _signed_observation(stack, challenge)
            signature = bytearray(base64.b64decode(body["signature_b64"]))
            signature[0] ^= 1
            body["signature_b64"] = base64.b64encode(signature).decode("ascii")
            return httpx.Response(200, json=body, request=request)

        client._http.close()
        client._http = httpx.Client(transport=httpx.MockTransport(invalid_signature_handler))
        with pytest.raises(LedgerError) as error:
            client.state(stack["resource_id"], stack["reader_id"])
        assert error.value.code == "INVALID_OBSERVATION_SIGNATURE"


def test_checkpoint_tampering_truncation_and_validator_head_rollback_fail_closed(stack, tmp_path):
    ledger = stack["ledger"]
    ledger.submit(stack["register"])
    checkpoint_path = tmp_path / "head.json"

    checkpoint_path.write_text("{damaged", encoding="utf-8")
    with pytest.raises(LedgerError) as error:
        LedgerClient("http://validator.local", ledger.config, checkpoint_path)
    assert error.value.code == "CHECKPOINT_INVALID"

    checkpoint_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "chain_id": ledger.chain_id,
                "genesis_hash": ledger.config["genesis_hash"],
                "head_height": 2,
                "head_hash": "a" * 64,
            }
        ),
        encoding="utf-8",
    )

    with _client_for(ledger, checkpoint_path) as client, pytest.raises(LedgerError) as error:
        client.state(stack["resource_id"], stack["reader_id"])
    assert error.value.code == "LEDGER_ROLLBACK"


def test_non_json_checkpoint_truncation_and_wrong_chain_checkpoint_are_rejected(stack, tmp_path):
    path = tmp_path / "head.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "chain_id": stack["ledger"].chain_id,
                "genesis_hash": stack["ledger"].config["genesis_hash"],
                "head_height": 0,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LedgerError) as error:
        LedgerClient("http://validator.local", stack["ledger"].config, path)
    assert error.value.code == "CHECKPOINT_INVALID"

    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "chain_id": "another-chain",
                "genesis_hash": stack["ledger"].config["genesis_hash"],
                "head_height": 0,
                "head_hash": stack["ledger"].config["genesis_hash"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LedgerError) as error:
        LedgerClient("http://validator.local", stack["ledger"].config, path)
    assert error.value.code == "CHECKPOINT_CONFIG_MISMATCH"
