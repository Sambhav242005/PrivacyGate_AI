# Native v2 execution evidence — 2026-10-26

## Result and scope

Implemented the approved academic v2 path: our single-validator permission
blockchain, password accounts, signed in-process sensor simulation, encrypted
SQLite payloads, evaluated Isolation Forest, and browser-decrypted reader insights.
The required path uses no EVM, wallet, Solidity, Anvil, MQTT broker or hosted AI.

This is a local academic demonstration, not production certification. Legacy v1
code/databases remain separate. No public deployment, external messages or paid
services were used. Existing uncommitted work was recorded before implementation;
pre-existing screenshot changes were restored from the binary baseline patch.
No commit was created.

## Environment and provenance

- Windows 11 build 26300, Intel64 Family 6 Model 183.
- Python 3.12.13, uv 0.11.26, Node 24.14.1, npm 11.11.0.
- Next 16.4.3, React 19.3.1, ESLint 10.13.0; Python versions resolved in uv.lock.
- Starting Git SHA: f0a5a3297d205c13a659da263921b201a7956e39. Results include
  uncommitted source changes; that SHA alone does not reproduce this working tree.
- Default chain ID privacygate-local-v2. Genesis/keys vary per isolated runtime;
  benchmark genesis is recorded in v2-benchmarks.json. No gas/fee claim applies.
- Local app exercised on web 3001, gateway 8001, validator 8010 because unrelated
  applications occupied default web/gateway ports. They were not stopped.

## Executed verification

From repository root:

```powershell
uv sync --locked --python 3.12
uv run --locked pytest -c pyproject.toml apps/gateway/tests/v2 tests/v2 -q
uv run --locked ruff check apps/gateway/src/privacygate_v2 apps/gateway/tests/v2 infra/scripts/v2 tests/v2
uv run --locked ruff format --check apps/gateway/src/privacygate_v2 apps/gateway/tests/v2 infra/scripts/v2 tests/v2
uv run --locked mypy apps/gateway/src/privacygate_v2
uv run --locked python infra/scripts/v2/bootstrap.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File infra/scripts/v2/Start.ps1 -Production -GatewayPort 8001 -WebPort 3001
```

Python: **28 passed** (latest complete lead run 23.64 seconds). Lead independently
ran the real process acceptance and full suite; the real process flow passed.
Ruff lint/format passed; mypy passed all nine source files. The independent
advisor separately ran the 27 backend tests successfully.

From apps/web, with NEXT_PUBLIC_GATEWAY_URL=http://127.0.0.1:8001 for builds:

```powershell
npm.cmd ci
npm.cmd run build
npm.cmd run tsc
npm.cmd run lint
npm.cmd run test
npm.cmd audit --json
$env:PG_WEB_URL='http://127.0.0.1:3001'
npx.cmd playwright test --reporter=line
```

Build, TypeScript and lint passed. Node disclosure tests: **6 passed**; these are
legacy shape checks, not evidence of v2 crypto interoperability. Browser suite:
**11 passed, 1 optional redundant credential-env test skipped**. The required v2
live test reads protected local credentials and fails rather than skipping if
setup is absent. It covers actual browser/WebCrypto decryption of Python-created
envelopes, owner registration, grant, anomaly, local key backup/import and revoke.
Other browser cases explicitly use mocked API state or the illustrative map.

Dependency audit: **0 vulnerabilities, all severities** after upgrading the
inherited Next 14 stack. Its initial audit had four high and one critical package
findings. No force/legacy-peer flags were used. npm ci still prints stale ESLint
peer-range warnings from underlying plugins; the installed documented combination
passes lint and build. Node module-detection and Starlette TestClient/httpx
deprecation warnings are nonfailing and remain visible.

Native PowerShell startup/stop and all-script parsing were exercised. Stop left
no listeners on our three ports or project Node processes. At a later conversation
interruption all managed services were found exited without an application error
in the inspected logs; restart/readiness and the recording rehearsal succeeded.
For independently persistent use, run the documented scripts in your own terminal.

## Acceptance traceability

All references below are v2 replacements of the earlier acceptance requirements.

| Cases | Evidence and actual boundary |
|---|---|
| T-01–T-05 | Signed ingest tests and real process simulation: valid, altered signature, replay, stale, malformed and wrong-device packets; atomic encrypted write and sequence race checks. MQTT topic binding is replaced by simulator/device binding. |
| T-06 | Strict schema/serializer and browser decrypted exact five-field assertion. Additional/private fields denied; no free-form AI release. |
| T-07, T-11 | Exact policy-component tests: resource/owner/reader/digest/scope/version/expiry, key version, fresh signed state. Expiry uses current time, not the last block timestamp. |
| T-08–T-10, T-16 | Actual Python→browser decryption; independent wrong-key/tamper failures; reader denied owner telemetry. |
| T-12–T-13 | Pending outbox never implies confirmed UI success; lost-response recovery; committed revoke blocks new/unread delivery; regrant never revives old queues. Single validator commits immediately rather than using an EVM mempool. |
| T-14 | Validator process stopped in real process test: reader HTTP503, simulator ingestion still accepted; restart recovers. |
| T-15 | Strict bodies, extra-field denial and direct reader/owner route checks; identity comes from the session, never request assignment. |
| T-17 | Password/session replacement: session expiry/hash storage/restart, CSRF/origin/Host, rate limiting and sanitized validation errors. EIP-191 is retired. |
| T-18 | Gateway DB/WAL scans lack raw field markers and plaintext insight event; chain transactions contain permission metadata only; reader HTML/HTTP excludes raw measurements; errors omit submitted secrets. No broker exists. This is targeted evidence, not a proof of zero leakage. |
| T-19–T-20 | Two distinct recipients, revoke one, other remains authorized; durable queue/session/sequence and service restart tests. |
| T-21–T-22 | Real ledger owner-only mutation, immutable registration, signature/replay/nonce/corruption/derived-state/checkpoint tests. |
| T-23 | Seeded held-out evaluation and model hash in v2-model-evaluation.json. |
| T-24 | Isolated fresh runtime provisioned by actual bootstrap and separate gateway/validator subprocesses; native startup and real browser journey. Remote clean-machine CI has been configured but not executed here. |

Additional tests cover precommit rollback, postcommit response loss, restart
reconciliation, terminal expiration of uncommitted transactions, signed absence,
clock regression, stale/replayed state observations, corrupted checkpoints and
head rollback. Reader backup clearing and honest logout failure recovery are
browser regression cases. Owner selection is locked during pending requests to
prevent delayed old-device telemetry from contaminating another device's page.

## Measured model and performance results

See v2-model-evaluation.json and v2-benchmarks.json for raw values/environment.
Train seed 2401: 512 normal samples. Held-out seeds 2402/2403: 256 normal and
128 anomalous samples; integer RPM. Fitted estimator hash and offset are recorded.

| Method | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Isolation Forest | 128 | 5 | 251 | 0 | 0.9624 | 1.0000 | 0.9808 |
| Rule baseline | 128 | 0 | 256 | 0 | 1.0000 | 1.0000 | 1.0000 |

The baseline performs better on this deliberately separable synthetic holdout.
No claim of field accuracy, failure prediction or AI superiority is supported.

Latest measured p95: grant HTTP→commit **22.89ms** (n=10); signed simulation through
encrypted dispatch **49.96ms** (n=40); authorized envelope HTTP fetch **14.28ms**
(n=40). Authorization plus encryption microbenchmark: custom chain **2.34ms**
versus in-memory ACL **0.087ms** (n=100 each). Revoke→observed denial **36.94ms**
was one sample only, not a reliable latency distribution. Sequential burst load,
single machine; stages do not establish sustained 1Hz performance. Percentiles
from separate stages must not be added as an end-to-end percentile.

## Review and routing

Independent advisor found stale pending-operation deadlock, pending-backup
retention, false logout success, then owner pagination races. All were fixed and
reviewed as resolved. The lead also fixed integration-harness client handling,
PowerShell JSON-array process stopping, and transient Windows benchmark cleanup.

| Role / requested model / effort | Assignments or consultations | Tokens / cached input / cache hit | Settings evidence |
|---|---:|---|---|
| Lead / current selection / unverified | 1 objective | Unavailable | Not exposed |
| Router / gpt-6-luna / low | 1 consultation | Unavailable | Dispatch only |
| Audit / gpt-6-luna / high | 1 assignment | Unavailable | Dispatch only |
| Blockchain / gpt-6-luna / max | 2 assignments including signed-absence repair | Unavailable | Dispatch only |
| Gateway / gpt-6.1-sol / high | 1 assignment including review fixes | Unavailable | Dispatch only |
| Web / gpt-6-luna / high | 2 assignments including receipts/pagination | Unavailable | Dispatch only |
| Dependency repair / gpt-6.1-sol / high | 1 repair assignment, legacy audit findings | Unavailable | Dispatch only |
| Advisor / gpt-6.1-sol / low | 4 consultations | Unavailable | Dispatch only |
| Unattributed usage | Unavailable | Unavailable | No token telemetry read |

Repairs above are included in their worker counts, not additional token totals.
For this one implementation objective: advisor use 1/1; router calls1, advisor
calls4. No token/cache cost or first-pass savings claim is possible. Append-only
events remain locally in ignored work/routing-harness/events.jsonl; this is not a
background collector and the scratch records are not published with the project.

Modern Web Guidance security guidance informed HttpOnly cookie use and memory-only
reader keys (“Set `HttpOnly` (`httpOnly: true`) on session and authentication cookies”). Current
FastAPI, Next/React migration, cryptography and uv documentation was consulted
through resolve-first Context7; docs were used before compatibility changes.

## Limits and remaining external verification

- Single validator and trusted gateway; no distributed consensus or protection
  from compromised signing hosts. Checkpoints do not defeat full trusted-host rewrite.
- Local password/reader backups are sensitive ignored runtime files. Do not share
  var/v2. Backups intentionally contain plaintext private material.
- One gateway worker. No public deployment or production-hardening claim.
- Cleanup of one failed benchmark's temporary directory was blocked by automatic
  approval review. That temporary local folder remains; the rejection did not
  affect application code or subsequent successful benchmark runs.
- Remote CI and an independent clean Windows machine were not run in this session.
- The reusable demo scripts and local recording are described in DEMO_V2.md.

## Recorded demonstration

Discovery and final rehearsal passed before recording. `node apps/web/e2e/v2-demo.cjs --record` completed every selector/action assertion and saved `docs/results/demo-privacygate-v2.webm`. Cursor/subtitles are injected on navigation; the file records the actual production UI and real local permission/crypto path. Script and discovery helper are retained under apps/web/e2e. Recovery secrets stay under ignored var/v2.

Final live browser extension additionally mutated nonce, ciphertext, AAD and key epoch in actual fetched envelopes: every mutation was rejected before display, then the original envelope decrypted successfully. A test initially chose the last device row while another demo registered equipment; this fixture-selection error was fixed by selecting its uniquely named equipment. The final full browser run passed 11 cases with only the optional redundant login case skipped.

Final WebM validation: VP9, 1280x720, 234.52 seconds, 18,248,492 bytes; ffprobe metadata and full ffmpeg decode exited0. The final screenshots were visually inspected.
