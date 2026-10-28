> **v2 supersession (2026-10-26):** The approved native custom-blockchain design in [V2.md](V2.md) governs new implementation. EVM/wallet/MQTT and incompatible v1 tooling/schema requirements below are historical. Completion requires dated v2 evidence, not the legacy checkboxes.

# TESTING.md — Verification Plan and Acceptance Matrix

> Tests described here are **requirements**, not passed test results. Report actual executions separately under `docs/results/`.

## Reviewed learning verification (PG-V2-007)

From repository root:

```powershell
uv run --locked pytest apps/gateway/tests/v2 tests/v2 -q
uv run --locked ruff check apps/gateway/src/privacygate_v2 apps/gateway/tests/v2 infra/scripts/v2 tests/v2
uv run --locked ruff format --check apps/gateway/src/privacygate_v2 apps/gateway/tests/v2 infra/scripts/v2 tests/v2
uv run --locked mypy apps/gateway/src/privacygate_v2
```

Learning tests use isolated temporary encrypted databases. They cover seeded
distribution shift, independent validation, non-improving activation rejection,
owner/resource scope, missing/expired examples, feature overlap, encrypted recipe
integrity, retention, writer contention, version mismatch, restart and rollback.
Gateway integration exercises the learned version with actual permission-ledger
state, recipient decryption, raw-data denial, revocation and a chain outage.
See [LEARNING.md](LEARNING.md) for the operator workflow and evaluation limits.

## Test layers

| Layer | Tool | Scope |
|---|---|---|
| Python unit | `pytest`, `pytest-cov` | Schemas, signed payloads, replay, canonicalization, filters, AI baseline, crypto |
| Contract unit/fuzz | Foundry `forge test` | Owner-only grant/revoke, expiry, version, digest, invalid addresses, ownership |
| HTTP contract | FastAPI `TestClient` / `httpx` | Exact status codes, ownership/IDOR, wallet sessions, response schemas |
| MQTT integration | Local Mosquitto | Topic ACL, QoS 1 duplicates, invalid signature and replay |
| Cross-component E2E | Docker/Anvil/Mosquitto + Playwright/pytest | Signed event → encrypted third-party result → revoke |
| Model evaluation | scikit-learn | Precision, recall, F1, false-positive rate, false-negative rate |
| Security-negative | pytest scripted adversarial inputs | Fail-closed, policy bypass, stale chain, nonce reuse, data leakage |
| Performance | Locust or bounded Python benchmark | Ingest-to-inference, dispatch latency, chain permission lookups |

## Reproducible run commands (once bootstrap scripts are implemented)

```bash
cp .env.example .env      # populate required test-only secrets; never commit .env
# Generate unique dev keys via project setup script, not by copying production keys.
docker compose up -d mqtt anvil
cd packages/contracts && forge test -vv
cd ../../apps/gateway && uv run pytest -q
cd ../simulator && uv run pytest -q
cd ../web && pnpm test
# From project root, when E2E harness has been implemented:
./infra/scripts/smoke.sh
```

These commands are the **intended interface**, not proof that supporting scripts already exist. On Windows, run shell scripts through WSL2; provide PowerShell alternatives in README if needed.

## Mandatory acceptance cases

| ID | Preconditions / action | Expected result |
|---|---|---|
| T-01 | Pinned device sends well-signed, valid schema and seq=1. | Reading stored encrypted exactly once. |
| T-02 | Change 1 byte of signed sensor payload. | Reject, no raw insert or event. |
| T-03 | Replay identical or smaller sequence from same device. | Reject/idempotently drop, no second event. |
| T-04 | Timestamp outside accepted ±30s skew. | Reject; log non-sensitive error only. |
| T-05 | Device publishes to another ID's topic. | Reject from ACL or ingress signature/ID checks. |
| T-06 | AI emits additional fields `gps`, `temp_c`, `explanation`. | Deterministic serializer rejects or strips; third-party never receives them. |
| T-07 | No active grant, wrong resource, wrong policy digest, wrong scope. | Do not queue, serve, or encrypt a new third-party output. |
| T-08 | Confirmed `READ_INSIGHT` grant, matching policy and registered recipient X25519 key. | Intended subscriber decrypts exact approved five fields. |
| T-09 | Another subscriber uses their own key against ciphertext. | AES-GCM tag validation fails. |
| T-10 | Subscriber requests owner `/telemetry` endpoint by guessing resource ID. | 403 or 404; no raw fields in response/error. |
| T-11 | Grant expired at gateway/chain observation time. | No future queued or fetched delivery. |
| T-12 | Owner submits `revoke`; transaction pending. | UI shows pending, security decision still uses confirmed chain state. |
| T-13 | `revoke` confirmed, sync observed; new anomaly emitted. | Revoked reader does not receive/decrypt a new envelope; queued unread items also become inaccessible. |
| T-14 | Chain RPC is unreachable or stale beyond configured freshness. | Third-party delivery fails closed, device ingest/local storage may continue. |
| T-15 | HTTP payload tries mass assignment `owner_wallet`, `scope=READ_DETAIL` for third party. | Validation/authorization rejects it. |
| T-16 | Tamper envelope's `nonce`, AAD, ciphertext, or key epoch. | Authentication/decryption fails. |
| T-17 | Duplicate/colliding wallet challenge, stale nonce, or replayed challenge. | Second login denied; challenge single-use. |
| T-18 | Inspect contract calldata/events, DB, application logs, broker retained messages. | No plaintext telemetry outside encrypted SQLite blob/owner authorized response. |
| T-19 | Two recipients with different grants; revoke one. | Other still receives independently encrypted future event; revoked one does not. |
| T-20 | Restart gateway, DB, broker. | Sequence counters and policy state persist; no replay acceptance. |
| T-21 | EVM contract unauthorized wallet calls grant/revoke. | Transaction reverts; events not emitted. |
| T-22 | Contract resource owner rotates/re-registers attempts. | Only explicit owner-approved path accepted; existing owner cannot be silently replaced. |
| T-23 | Simulated anomaly fixtures labeled train/test disjoint. | Metrics report confusion matrix, dataset seeds and model version. |
| T-24 | Fresh clone follows quickstart. | Two readers, one event, grant and revoke reproduced without manual DB edits. |

## Security invariants to assert programmatically

```python
SUBSCRIBER_FIELDS = {
    'event_id', 'event_type', 'severity', 'observed_at', 'model_version'
}
assert set(decrypted_insight) == SUBSCRIBER_FIELDS
assert not ({'temp_c', 'vibration_mm_s', 'rpm', 'gps'} & set(decrypted_insight))
```

Also scan serialized HTTP/WS/MQTT output and application logs for generated secret fixture markers, not only JSON property names. Never print real secret material during these scans.

## Dataset and AI correctness

- Produce seeded normal and abnormal synthetic traces with known labels. Keep simulation-generator code and distribution parameters versioned.
- Fit training model only on training data; reserve held-out test traces. Explain if Isolation Forest is trained on normal-only data and why a threshold was selected.
- Compare anomaly model to a deterministic rule-based baseline on **the same held-out data**.
- Report TP, FP, TN, FN, precision, recall, F1, false-positive rate; provide denominators. Avoid invented values or accuracy without prevalence context.
- Track model file hash and inference time per run. This is **not** equipment failure prediction validation.

## Performance measurement

Measure independently: MQTT receive→stored, stored→AI, AI→allowed encrypted envelope, envelope→subscriber HTTP response, contract-grant confirmation and revoke sync delay. Record p50/p95/p99, count, environment, CPU and synthetic input rate. No single end-to-end number should mix contract grant time with ongoing message delivery. Target p95 <2s at 1 sensor / 1Hz local lab load (aspirational, not guaranteed).

## CI gates

- Required: format, lint, type checking, isolated unit tests, Foundry tests, API schema consistency, test fixtures free of secrets.
- Before merging auth/crypto/policy: add or revise negative tests; 100% of the required negative cases for touched code must pass.
- Before declaring MVP complete: `T-01` to `T-24` marked with pass/fail evidence and explanations for any deviation.

## Failure reports

Store `docs/results/YYYY-MM-DD-run-id.md` with git SHA, OS/Python/Node/Foundry versions, Anvil chain ID, seed, model hash, test commands, log excerpt (redacted), results and known limitations. Log recurring errors in `MISTAKES.md`; do not silently weaken tests to obtain a pass.
