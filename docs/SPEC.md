> **v2 supersession (2026-10-26):** The approved native custom-blockchain design in [V2.md](V2.md) governs new implementation. EVM/wallet/MQTT and incompatible v1 tooling/schema requirements below are historical. Completion requires dated v2 evidence, not the legacy checkboxes.

# SPEC.md — PrivacyGate AI Product Specification

## 1. Identity and status

- **Title:** PrivacyGate AI — Blockchain-Based Privacy-Preserving IoT Intelligence Exchange
- **Group:** 24 | **Student:** Sambhav Surana | **Enrollment:** 23100BTCSAII14318
- **Guide:** Prof. Rohit Choubey | **Program:** B.Tech, Artificial Intelligence & Data Science
- **Stage:** proposed academic MVP; features remain unimplemented until tested.
- **Project principle:** share minimum useful **insight**, not unrestricted raw device data.

## 2. Problem statement

An IoT operator may want external maintenance, insurance or logistics applications to learn whether an event occurred, without distributing every sensor measurement. Centralized integrations often use broad credentials and provide limited independent evidence of grant/revoke changes. PrivacyGate AI demonstrates restricted insight disclosure based on owner-controlled, chain-verifiable authorization, with the privacy gate separate from the AI predictor.

## 3. One-feature MVP

**Owner-controlled selective insight delivery:** a simulated industrial machine publishes signed telemetry locally; an AI model produces a machine-anomaly insight; a third-party subscriber receives a schema-limited, recipient-encrypted insight only while the owner's on-chain grant is active. The owner sees local detailed telemetry.

### Personas

| Persona | Identity | Objective | Allowed data |
|---|---|---|---|
| Device publisher | Pinned Ed25519 device ID | Submit readings | Publish only; no read/grant rights |
| Owner | EVM wallet authenticated to gateway | Observe and administer machine | Own raw readings + policy control |
| Third-party subscriber | Separate EVM wallet + X25519 recipient key | Monitor abnormal machine behavior | Allowed encrypted `MACHINE_ANOMALY` insights only |
| Gateway | Trusted local process | Ingest, infer, enforce, encrypt | Local raw data; must not expand authorization |
| Evaluator | Local test runner | Verify claims and compare overhead | Synthetic fixtures and test outputs |

## 4. Demonstration scenario

1. Start local Anvil, MQTT broker, FastAPI gateway, local SQLite and React web UI.
2. Owner registers a simulated machine (`resource_id`) and pinned device signing key.
3. Simulator publishes temperature, vibration and RPM with a valid signature and monotonic sequence.
4. Gateway stores encrypted raw reading, runs local anomaly detection and emits a candidate insight.
5. Owner creates a narrow off-chain policy: `MACHINE_ANOMALY`, approved summary fields, recipient wallet, expiration.
6. Owner grants `READ_INSIGHT` on-chain with the policy digest and synchronizes confirmed contract state.
7. Gateway validates candidate insight against the fixed schema and granted policy; encrypts separately for recipient; delivers by authenticated HTTPS polling.
8. Owner sees detailed telemetry; subscriber decrypts only the narrow event.
9. Owner revokes on-chain. After confirmed state refresh, subsequent events are not packaged for the revoked recipient; old historical copies remain unrecoverable by revocation.
10. Show negative tests, permission receipt and latency/precision metrics without fabricated values.

## 5. Functional requirements

| ID | Requirement | Acceptance evidence |
|---|---|---|
| FR-01 | Owner can enroll a resource/device and pin its publisher Ed25519 public key. | Unauthorized registration denied. |
| FR-02 | Signed telemetry is schema-valid, fresh and replay-protected. | Valid input accepted; altered signature and duplicate sequence rejected. |
| FR-03 | Raw telemetry is only stored encrypted on local disk. | SQLite inspection lacks plaintext reading payload. |
| FR-04 | Local AI emits fixed `MACHINE_ANOMALY` candidate events; baseline comparator exists. | Model and rule baseline run on labeled synthetic fixtures. |
| FR-05 | Owner prepares narrowly scoped, expiring policy and registers its digest on-chain. | Digest and contract grant match current local policy. |
| FR-06 | Third-party outputs pass an independent deterministic field/type allowlist. | Adding unexpected model fields does not disclose them. |
| FR-07 | Approved insight is authenticated-encrypted for individual recipient. | Intended recipient decrypts; others fail. |
| FR-08 | Owner can inspect detailed readings; third party cannot call owner-only endpoints. | Direct endpoint/IDOR tests reject third party. |
| FR-09 | Revocation/expiry stops future delivery after confirmed sync. | Post-sync retrieval and newly generated delivery denied. |
| FR-10 | Contract receipts and audit state can be inspected. | Indexed block/tx info corresponds to confirmed contract reads. |
| FR-11 | Loss of blockchain connectivity blocks new third-party disclosures. | Outage test passes fail-closed behavior. |
| FR-12 | A one-command or documented scripted demo is repeatable. | Clean-machine acceptance run. |

## 6. Non-functional requirements

- **Security:** no raw telemetry in contract, transaction calldata, MQTT subscriber topics, HTTP third-party responses, browser logs or third-party notification text. Logs must redact payloads and secrets.
- **Availability:** local ingestion and processing may continue during chain outage, but third-party delivery is suspended (fail closed). Queued data must not be backfilled without authorization at the time of delivery.
- **Correctness:** authorization checked on both candidate dispatch and retrieval. Treat pending transactions as ineffective. Ensure same code validates across tests and production paths.
- **Auditability:** capture chain ID, block number, transaction hash and grant version for confirmed actions; do not claim logs independently prove honest inference or honest sensors.
- **Reproducibility:** synthetic seed/configuration version fixed; record dataset version, model version and threshold.
- **Compatibility:** developer experience on Windows + WSL2 or Linux; dockerized infrastructure is acceptable; CPU-only AI.
- **Targets (engineering goals, not measured results):** p95 local insight delivery after classification < 2 seconds under single-sensor lab load, excluding grant transaction time; 100% pass rate for defined authorization-negative tests; no plaintext raw telemetry in persisted SQLite payloads. Record actual results and environment.
- **Ethics/privacy:** synthetic data only in demo; no physical safety, insurance pricing or medical decisions based on the model.

## 7. Data boundaries

### Raw telemetry (owner-only)
`temp_c`, `vibration_mm_s`, `rpm`, timestamp, device/sequence identifiers.

### Candidate AI event (gateway-local)
Fixed, validated enum/type: `MACHINE_ANOMALY`; severity `LOW|MEDIUM|HIGH`; observation timestamp; model version; event ID. Detailed scores or source readings remain local.

### Third-party insight (allowed schema)
Exactly: `event_id`, `event_type`, `severity`, `observed_at`, `model_version`. No `temp_c`, `vibration_mm_s`, `rpm`, location, free-form model explanation or arbitrary metadata.

### Blockchain record
Resource commitment/id, EVM wallet addresses, policy digest, coarse scope, expiry, version, grant/revoke status and event receipts. **These values may still reveal relationships**; do not use real identities in the demo.

## 8. Explicitly out of scope

Commercial car APIs; production sensor trust/attestation; payment tokens; incentivized marketplaces; a custom blockchain or consensus protocol; storing continuous readings on-chain; global IoT discovery; federated learning; unrestricted LLM tools/SQL; guaranteed anomaly diagnosis; distributed key management; confidential computing/ZK inference proofs; full user-account recovery; production security certification.

## 9. Definition of success

A reviewer on a local lab setup can watch one anomaly travel from a signed publisher to a permitted encrypted subscriber, compare an owner vs external subscriber's data, revoke and observe future delivery blocked, verify blockchain transaction details, and reproduce at least one negative test for each security boundary. Results must be backed by test logs and documented methodology.

## 10. Sources of truth

Implementation interfaces: `API.md`, `DATA_MODEL.md`; threat model: `DESIGN.md`; known decisions: `DECISIONS.md`; executable verification: `TESTING.md`; delivery order: `TASKS.md`.
