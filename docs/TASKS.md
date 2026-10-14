# TASKS.md — Solo-Developer Implementation Roadmap

> **Status:** All tasks below are **planned**. Mark `[x]` only after implementation, passing tests and evidence. Dependencies are explicit so multiple coding agents can safely work in parallel.

## Milestones and acceptance gates

| Milestone | Deliverable | Gate |
|---|---|---|
| M0 | Repository + local services | Fresh clone boots predictable dev environment |
| M1 | Signed telemetry / encrypted storage | T-01..T-05 and DB encryption check |
| M2 | Local AI + strict disclosure schema | T-06, T-23 and model evaluation report |
| M3 | Solidity registry + wallet auth | T-07, T-12, T-17, T-21, T-22 |
| M4 | Per-recipient encryption + delivery | T-08..T-11, T-16, T-19 |
| M5 | Revocation and fail-closed behavior | T-13..T-15, T-20 |
| M6 | Frontend + polished E2E demonstration | T-18, T-24, latency and comparative measurements |

## Phase 0 — Scope and bootstrap

- [ ] **PG-001 — Repository skeleton.** Create folders per `Project-Structure.md`; README, ignore rules, basic README architecture section. **Depends:** none. **Done:** lints pass in CI stub, no secrets committed.
- [ ] **PG-002 — Toolchain and dev services.** Python 3.11+, `uv`, pnpm, Foundry, Docker Compose, local Anvil and Mosquitto bound to loopback; `.env.example` loader and safe key generator. **Depends:** PG-001. **Done:** fresh startup documented and reproducible.
- [ ] **PG-003 — Shared golden DTO fixtures.** Pydantic/JSON schema and canonical JSON/digest reference samples for telemetry, policy manifest, insight, envelope; JS/Python tests agree. **Depends:** PG-001. **Done:** `API.md` request/response round-trip tests.

## Phase 1 — Device ingest and local privacy

- [ ] **PG-010 — Device enrollment + pinned Ed25519 pubkeys.** Domain records and authenticated owner endpoint. **Depends:** PG-003, PG-020 (contract ownership prerequisite). **Done:** unauthorized enrollment rejected.
- [ ] **PG-011 — Telemetry simulator.** Repeatable seeded normal/anomalous sensor traces, monotonic sequence, sign canonical JSON, MQTT QoS 1 retained=false. **Depends:** PG-002, PG-003. **Done:** valid and invalid fixture modes.
- [ ] **PG-012 — MQTT ingestion validation.** Broker ACL, topic-device binding, Ed25519 verify, schema/range, clock window, replay check and 409/metrics semantics. **Depends:** PG-010, PG-011. **Done:** T-01..T-05.
- [ ] **PG-013 — SQLite encryption & atomic writes.** AES-GCM payload columns, migration scripts, no telemetry logs; sequence and record in one transaction. **Depends:** PG-012. **Done:** raw values absent from inspected SQLite/log output; restart persists counters.

## Phase 2 — AI and policy-filtered output

- [ ] **PG-014 — Synthetic dataset generator.** Fixed seed, splits, normal/anomaly tags, license note. **Depends:** PG-011. **Done:** reproducible labeled CSV fixtures.
- [ ] **PG-015 — Local anomaly model and baseline.** CPU Isolation Forest + thresholded rule baseline; `model_version`; no hosted inference. **Depends:** PG-014. **Done:** confusion matrix, precision/recall/F1 and labeled holdout analysis; T-23.
- [ ] **PG-016 — Strict candidate → InsightV1 serializer.** Only five approved fields and event type; forbid arbitrary model fields or explanations. **Depends:** PG-003, PG-015. **Done:** T-06 and known-field leakage scan.

## Phase 3 — Blockchain and authorization

- [ ] **PG-020 — PermissionRegistry smart contract.** Resource ownership, grant/revoke, expiry parameters, fixed scope=1, version increments and events. **Depends:** PG-002, PG-003. **Done:** Foundry unauthorized access/revoke/fuzz tests T-21/T-22.
- [ ] **PG-021 — Contract deploy + generated ABI.** Deploy local Anvil, pin expected chain ID/address, surface ABI to web/gateway. **Depends:** PG-020. **Done:** documented deterministic local deployment (address may change on resets).
- [ ] **PG-022 — EIP-191 authentication and CSRF.** Single-use nonce, wallet recovery, secure session, logout, throttling, origin checks. **Depends:** PG-003. **Done:** T-17, cookie attributes tested.
- [ ] **PG-023 — Policy draft/digest service.** Owner creates narrowly allowed manifest; canonical SHA-256; only supported scopes; immutable revisions. **Depends:** PG-003, PG-022. **Done:** Python/TS digest fixtures identical.
- [ ] **PG-024 — Confirmed-chain sync and policy gate.** Validate tx and current contract view, digest, wallet, resource, expiry, scope; no permissions from supplied tx hash alone. **Depends:** PG-020..PG-023, PG-016. **Done:** T-07, T-12, T-14.

## Phase 4 — Encrypted third-party delivery

- [ ] **PG-030 — Wallet-bound recipient X25519 key enrollment.** Key length checks, user ownership, key change invalidates unread envelopes. **Depends:** PG-022. **Done:** other users cannot overwrite key.
- [ ] **PG-031 — Envelope crypto.** Ephemeral X25519 + HKDF + AES-GCM with canonical AAD and per-delivery context; nonce/key tests. **Depends:** PG-003, PG-030. **Done:** T-09, T-16 cross-key/tamper tests.
- [ ] **PG-032 — Policy-checked dispatch + encrypted queue.** Create per-recipient ciphertext from InsightV1 only after fresh chain authorization. **Depends:** PG-016, PG-024, PG-031. **Done:** T-08 and no plaintext in queue.
- [ ] **PG-033 — Subscriber read API and owner telemetry API.** Authenticated, paginated, owner-only raw decrypt endpoint, subscriber only encrypted envelope; repeat chain check at read. **Depends:** PG-013, PG-022, PG-032. **Done:** T-08, T-10, T-11, T-15.
- [ ] **PG-034 — Revocation/expiry sync and key epoch.** Block fresh and unread delivery after confirmed revoke; increment epoch; no retroactive claims. **Depends:** PG-024, PG-032, PG-033. **Done:** T-13, T-19.

## Phase 5 — UI and integration

- [ ] **PG-040 — Owner dashboard.** Enroll machine, show detailed telemetry, create policy draft, send owner-signed wallet tx, show receipt states, revoke. **Depends:** PG-021, PG-023, PG-033, PG-034. **Done:** end-to-end browser scenario.
- [ ] **PG-041 — Subscriber dashboard.** Login, enroll own encryption public key, request envelopes, client-side decrypt, show permitted insight only. **Depends:** PG-030..PG-033. **Done:** no localStorage secret; T-08/T-09.
- [ ] **PG-042 — Automated E2E test rig.** Start Anvil/MQTT/gateway/simulator/web, provision synthetic wallets, grant/emit/revoke; inject chain outage. **Depends:** PG-040, PG-041. **Done:** T-01..T-24 with command output.
- [ ] **PG-043 — Security review.** Verify no raw payload in chain/broker/logs/unauthorized HTTP, secret scan, key lifecycle, replay. **Depends:** PG-042. **Done:** T-18 plus documented threat-model checklist.
- [ ] **PG-044 — Benchmarks and centralized baseline.** Measure p50/p95/p99, model metrics, contract confirmation/revocation delay; compare with simple local ACL variant. **Depends:** PG-042. **Done:** no invented measurements; `docs/results/` report.
- [ ] **PG-045 — Academic demo/package.** README setup, architecture diagram, screenshots, known limitations, live 5-minute walkthrough and cleanup instructions. **Depends:** PG-043, PG-044. **Done:** new reviewer can reproduce T-24.

## Definition of Done for each task

- [ ] Code is narrow, reviewed and follows conventions.
- [ ] Positive and **negative** tests pass with evidence.
- [ ] No unexpected contract/API/schema behavior or privacy leakage.
- [ ] `.env.example` updated if settings changed; no secrets checked in.
- [ ] Relevant docs and ADRs updated.
- [ ] Task box checked with link/path to test run artifact.

## Suggested order for a solo developer

Start PG-001, PG-002, PG-003, PG-020, PG-021, PG-022, PG-010, PG-011, PG-012, PG-013. Then finish AI, grant sync, cryptography and reader endpoint before investing in dashboards. Mock the UI against `API.md`, but do not treat mock authorization as finished security functionality.

## Time-box fallback (if academic deadline approaches)

Preserve the core demonstration in this order: signed input → encrypted local storage → deterministic anomaly **baseline** → strict schema → verified chain grant → recipient encryption → revoke denial → minimal UI. Postpone ML-vs-rule benchmark polish, elaborate charts and optional additional sensor types. Never cut permission enforcement or negative tests to save time.
