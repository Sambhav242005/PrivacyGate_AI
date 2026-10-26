"""Bounded measured synthetic benchmark against real loopback validator/gateway."""

from __future__ import annotations

import base64
import importlib.util
import json
import platform
import statistics
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/gateway/src"))


def summary(samples):
    ordered = sorted(samples)

    def percentile(p):
        index = (len(ordered) - 1) * p
        lower = int(index)
        upper = min(lower + 1, len(ordered) - 1)
        return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)

    return {
        "n": len(samples),
        "unit": "milliseconds",
        "p50": statistics.median(samples),
        "p95": percentile(0.95),
        "p99": percentile(0.99),
    }


def timed(samples, fn):
    start = time.perf_counter()
    value = fn()
    samples.append((time.perf_counter() - start) * 1000)
    return value


@contextmanager
def temporary_runtime():
    temporary = tempfile.TemporaryDirectory(prefix="privacygate-bench-")
    try:
        yield temporary.name
    finally:
        # Windows scanners may briefly retain handles after child processes exit.
        for attempt in range(5):
            try:
                temporary.cleanup()
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.25)


def main():
    from privacygate_v2.ledger_client import LedgerClient
    from privacygate_v2.security import encrypt_envelope

    spec = importlib.util.spec_from_file_location(
        "v2_process_test", ROOT / "tests/v2/test_process_flow.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "os": platform.platform(),
        "cpu": platform.processor(),
        "seed": 2401,
        "limitation": "Single-host synthetic benchmark, sequential burst load. ACL comparison isolates authorization plus envelope encryption, not total ingest pipeline or equivalent distributed trust.",
    }
    with temporary_runtime() as tmp:
        runtime = module.Runtime(Path(tmp) / "runtime")
        try:
            runtime.start("validator")
            runtime.start("gateway")
            with runtime.login("owner") as owner, runtime.login("reader") as reader:
                require = module.require
                device = require(
                    owner.post("/v2/devices", json={"name": "Benchmark synthetic compressor"})
                )
                resource = device["resource_id"]
                recipient = runtime.credentials["reader"]["account_id"]
                private = X25519PrivateKey.generate()
                key = require(
                    reader.post(
                        "/v2/keys",
                        json={
                            "x25519_public_key_b64": base64.b64encode(
                                private.public_key().public_bytes_raw()
                            ).decode(),
                            "replace": False,
                        },
                    )
                )
                commits, pipelines, fetches, revocations = [], [], [], []
                for _ in range(10):
                    policy = timed(
                        commits,
                        lambda: require(
                            owner.post(
                                "/v2/policies",
                                json={
                                    "resource_id": resource,
                                    "recipient_id": recipient,
                                    "expires_at": int(time.time()) + 1800,
                                },
                            )
                        ),
                    )
                for _ in range(40):
                    result = timed(
                        pipelines,
                        lambda: require(
                            owner.post(
                                "/v2/simulator",
                                json={"resource_id": resource, "mode": "anomaly", "count": 1},
                            )
                        ),
                    )
                    assert result["accepted"] == 1
                    envelopes = timed(
                        fetches,
                        lambda: require(
                            reader.get("/v2/insights", params={"resource_id": resource})
                        ),
                    )
                    assert envelopes["items"]
                client = LedgerClient(runtime.config["chain"]["url"], runtime.config["chain"])
                state = client.state(resource, recipient)
                local_grant = state["grant"]
                insight = {
                    "event_id": str(uuid.uuid4()),
                    "event_type": "MACHINE_ANOMALY",
                    "severity": "HIGH",
                    "observed_at": datetime.now(UTC)
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
                    "model_version": "benchmark-fixed-insight-v2",
                }

                def release(grant):
                    assert grant["active"] and grant["scope"] == "READ_INSIGHT"
                    assert grant["expires_at"] > time.time()
                    assert grant["policy_digest"] == policy["policy_digest"]
                    return encrypt_envelope(
                        insight, resource, recipient, grant["version"], key, str(uuid.uuid4())
                    )

                chain_release, acl_release = [], []
                for _ in range(100):
                    timed(
                        chain_release, lambda: release(client.state(resource, recipient)["grant"])
                    )
                    timed(acl_release, lambda: release(local_grant.copy()))
                start = time.perf_counter()
                require(owner.post(f"/v2/policies/{policy['policy_id']}/revoke", json={}))
                require(reader.get("/v2/insights", params={"resource_id": resource}), 403)
                revocations.append((time.perf_counter() - start) * 1000)
                report["measurements"] = {
                    "grant_http_to_commit": summary(commits),
                    "signed_simulator_through_encrypted_dispatch": summary(pipelines),
                    "authorized_envelope_http_fetch": summary(fetches),
                    "chain_authorization_plus_encryption": summary(chain_release),
                    "in_memory_acl_authorization_plus_encryption": summary(acl_release),
                    "revoke_http_to_observed_denial": summary(revocations),
                }
                report["chain"] = {
                    "chain_id": runtime.config["chain"]["chain_id"],
                    "genesis_hash": runtime.config["chain"]["genesis_hash"],
                }
                client.close()
        finally:
            runtime.close()
    output = ROOT / "docs/results/v2-benchmarks.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Measured benchmark written to {output}")


if __name__ == "__main__":
    main()
