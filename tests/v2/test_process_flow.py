"""Actual loopback processes: no mocked chain, transport, auth, or encryption."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[2]
ORIGIN = {"Origin": "http://127.0.0.1:3000"}


def canon(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def decrypt(envelope, private):
    aad = base64.b64decode(envelope["aad_b64"], validate=True)
    header = json.loads(aad)
    assert set(header) == {
        "schema_version",
        "delivery_id",
        "event_id",
        "resource_id",
        "recipient_id",
        "policy_version",
        "key_version",
        "key_epoch",
    }
    assert canon(header) == aad
    for key in set(header) - {"event_id"}:
        assert header[key] == envelope[key]
    info = b"privacygate-envelope-v2|" + canon(
        {
            key: header[key]
            for key in (
                "event_id",
                "key_epoch",
                "key_version",
                "policy_version",
                "recipient_id",
                "resource_id",
            )
        }
    )
    shared = private.exchange(
        X25519PublicKey.from_public_bytes(base64.b64decode(envelope["ephemeral_public_key_b64"]))
    )
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=info).derive(shared)
    payload = AESGCM(key).decrypt(
        base64.b64decode(envelope["nonce_b64"]), base64.b64decode(envelope["ciphertext_b64"]), aad
    )
    result = json.loads(payload)
    assert set(result) == {"event_id", "event_type", "severity", "observed_at", "model_version"}
    assert result["event_id"] == header["event_id"]
    return result


class Runtime:
    def __init__(self, path):
        spec = importlib.util.spec_from_file_location(
            "v2_bootstrap", ROOT / "infra/scripts/v2/bootstrap.py"
        )
        bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)
        self.path = path
        self.config_path = bootstrap.bootstrap(path)
        self.config = json.loads(self.config_path.read_text())
        self.validator_port, self.gateway_port = available_port(), available_port()
        self.config["chain"]["url"] = f"http://127.0.0.1:{self.validator_port}"
        self.config_path.write_text(json.dumps(self.config))
        self.credentials = {
            item["username"]: item for item in json.loads((path / "credentials.json").read_text())
        }
        self.processes = {}
        self.logs = []

    def start(self, service):
        port = self.validator_port if service == "validator" else self.gateway_port
        log = (self.path / f"{service}.log").open("ab")
        self.logs.append(log)
        env = {**os.environ, "PYTHONPATH": str(ROOT / "apps/gateway/src")}
        process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "infra/scripts/v2/serve.py"),
                service,
                "--config",
                str(self.config_path),
                "--port",
                str(port),
            ],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=log,
        )
        self.processes[service] = process
        url = f"http://127.0.0.1:{port}" + ("/health" if service == "validator" else "/v2/health")
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(
                    f"{service} exited before readiness; inspect {self.path / (service + '.log')}"
                )
            try:
                if httpx.get(url, timeout=1).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            time.sleep(0.1)
        raise AssertionError(f"{service} readiness timeout")

    def stop(self, service):
        process = self.processes.pop(service, None)
        if process:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    def close(self):
        for service in list(self.processes):
            self.stop(service)
        for log in self.logs:
            log.close()

    @contextmanager
    def login(self, name):
        client = httpx.Client(
            base_url=f"http://127.0.0.1:{self.gateway_port}", headers=ORIGIN, timeout=30
        )
        try:
            account = self.credentials[name]
            response = client.post(
                "/v2/auth/login", json={k: account[k] for k in ("username", "password")}
            )
            assert response.status_code == 200, response.text
            client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
            yield client
        finally:
            client.close()


def require(response, status=200):
    assert response.status_code == status, response.text
    return response.json()


@pytest.fixture
def runtime(tmp_path):
    result = Runtime(tmp_path / "runtime")
    try:
        result.start("validator")
        result.start("gateway")
        yield result
    finally:
        result.close()


def test_actual_process_grant_encrypt_revoke_outage_restart(runtime):
    with (
        runtime.login("owner") as owner,
        runtime.login("reader") as reader,
        runtime.login("reader2") as other,
    ):
        # Browser-facing authentication is real; mutation without CSRF is denied.
        token = owner.headers.pop("X-CSRF-Token")
        require(owner.post("/v2/devices", json={"name": "Synthetic compressor"}), 403)
        owner.headers["X-CSRF-Token"] = token
        device = require(owner.post("/v2/devices", json={"name": "Synthetic compressor"}))
        resource = device["resource_id"]
        recipient = runtime.credentials["reader"]["account_id"]
        keys = [X25519PrivateKey.generate(), X25519PrivateKey.generate()]
        for client, key in zip((reader, other), keys):
            public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
            enrolled = require(
                client.post("/v2/keys", json={"x25519_public_key_b64": public, "replace": False})
            )
            restored = require(
                client.post("/v2/keys", json={"x25519_public_key_b64": public, "replace": False})
            )
            assert restored["key_version"] == enrolled["key_version"]
        policies = []
        for name in ("reader", "reader2"):
            policy = require(
                owner.post(
                    "/v2/policies",
                    json={
                        "resource_id": resource,
                        "recipient_id": runtime.credentials[name]["account_id"],
                        "expires_at": int(time.time()) + 600,
                    },
                )
            )
            assert policy["receipt"]["block_hash"]
            policies.append(policy)
        require(reader.get(f"/v2/resources/{resource}/telemetry"), 403)
        for mode in ("tampered", "replayed", "stale", "malformed", "wrong-device"):
            result = require(
                owner.post(
                    "/v2/simulator", json={"resource_id": resource, "mode": mode, "count": 1}
                )
            )
            assert result["rejected"] >= 1
        result = require(
            owner.post(
                "/v2/simulator", json={"resource_id": resource, "mode": "anomaly", "count": 2}
            )
        )
        assert result["accepted"] == 2
        page = require(reader.get("/v2/insights", params={"resource_id": resource}))
        assert page["items"], "Actual anomalous sensor input must create encrypted delivery"
        envelope = page["items"][0]
        assert envelope["recipient_id"] == recipient
        insight = decrypt(envelope, keys[0])
        assert insight["event_type"] == "MACHINE_ANOMALY"
        with pytest.raises(InvalidTag):
            decrypt(envelope, keys[1])
        tampered = {**envelope, "ciphertext_b64": base64.b64encode(bytes(64)).decode()}
        with pytest.raises(InvalidTag):
            decrypt(tampered, keys[0])
        raw = require(owner.get(f"/v2/resources/{resource}/telemetry"))
        assert raw["items"] and "temp_c" in raw["items"][0]
        runtime.stop("gateway")
        runtime.start("gateway")
        # Existing cookie sessions and encrypted deliveries must survive restart.
        assert require(reader.get("/v2/me"))["account_id"] == recipient
        assert require(reader.get("/v2/insights", params={"resource_id": resource}))["items"]
        revoked = require(owner.post(f"/v2/policies/{policies[0]['policy_id']}/revoke", json={}))
        assert revoked["status"] == "REVOKED"
        require(reader.get("/v2/insights", params={"resource_id": resource}), 403)
        require(
            owner.post(
                "/v2/simulator", json={"resource_id": resource, "mode": "anomaly", "count": 1}
            )
        )
        assert require(other.get("/v2/insights", params={"resource_id": resource}))["items"]
        runtime.stop("validator")
        require(other.get("/v2/insights", params={"resource_id": resource}), 503)
        assert (
            require(
                owner.post(
                    "/v2/simulator", json={"resource_id": resource, "mode": "anomaly", "count": 1}
                )
            )["accepted"]
            == 1
        )
        runtime.start("validator")
        assert require(other.get("/v2/insights", params={"resource_id": resource}))["items"]
        # A new grant cannot resurrect old delivery versions.
        require(
            owner.post(
                "/v2/policies",
                json={
                    "resource_id": resource,
                    "recipient_id": recipient,
                    "expires_at": int(time.time()) + 600,
                },
            )
        )
        assert require(reader.get("/v2/insights", params={"resource_id": resource}))["items"] == []
        require(
            owner.post(
                "/v2/simulator", json={"resource_id": resource, "mode": "anomaly", "count": 1}
            )
        )
        assert require(reader.get("/v2/insights", params={"resource_id": resource}))["items"]
