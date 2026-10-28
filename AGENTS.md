# AGENTS.md — PrivacyGate AI Coding-Agent Instructions

> **Authority:** This file governs work by coding agents in this repository. It describes the *proposed* project; do not report planned features as implemented. Based on the Group 21 PrivacyGate AI academic synopsis.

## Mission

Build a reproducible, security-conscious academic MVP showing **one signed industrial IoT sensor → one local AI gateway → two distinct reader views**. A device owner can see detailed telemetry; a third-party reader can receive only encrypted, owner-authorized AI insights. Owner-managed authorization is anchored in a local Ethereum-compatible smart contract.

## Documents and precedence

Read before changing code, in this order:

1. `docs/SPEC.md` — product scope and acceptance criteria.
2. `docs/DECISIONS.md` — binding architectural decisions, including trust boundaries.
3. `docs/DESIGN.md` — components, protocols, security assumptions, failure modes.
4. `docs/API.md` and `docs/DATA_MODEL.md` — authoritative interface and persistence contracts.
5. `docs/CONVENTIONS.md` — names, style, commits, safety, PR checklist.
6. `docs/TESTING.md` — proof required before claiming a feature complete.
7. `docs/TASKS.md` — milestones and task dependencies.
8. `Project-Structure.md` — intended filesystem ownership.
9. `docs/MISTAKES.md` — lessons, common failure modes, and future incident log.

When docs conflict, **STOP and reconcile** instead of guessing. Document significant changes as an ADR in `docs/DECISIONS.md`; update contract, API, model, tests, and `.env.example` together.

## Non-negotiable security rules

- **No raw telemetry, coordinates, prompts, plaintext insights, device keys, API tokens, or personal data on-chain.** Public wallet addresses and hashes can still be linkable.
- Never let the AI grant permissions, execute arbitrary SQL, choose unrestricted output fields, or bypass deterministic validation.
- A reader with `READ_INSIGHT` must *never* access plaintext raw telemetry through HTTP, MQTT, events, logs, errors, or frontend assets.
- Enforce authorization **on every publication AND retrieval** using current confirmed contract state; a UI role check is not access control.
- **Fail closed** for third-party disclosure on uncertain, expired, mismatched, or unreachable chain state.
- Device input requires signature verification, pinned device public key, fresh timestamp, strict per-device sequence/replay defense, size limits, and schema validation.
- Encrypt raw telemetry **application-side** before SQLite persistence; encrypt every approved insight **for its specific recipient** before delivery.
- Never commit secret keys or real telemetry. Local Anvil accounts are development-only; never use them on real networks.
- Revocation takes effect for **future delivery after the on-chain transaction is confirmed and gateway state refreshed**. It cannot erase what a reader already decrypted.
- No claims of trusted sensor provenance, certified AI accuracy, zero leakage, or fully decentralized consensus from a local Anvil demo.

## Working protocol for every task

1. Identify a `docs/TASKS.md` ID, dependencies, expected deliverables and affected contracts.
2. Inspect current repository state; do not overwrite unrelated work.
3. State assumptions and minimal implementation plan before large changes.
4. Implement one small vertical slice with matching unit tests and integration tests.
5. Run formatting/lint/type checks, relevant tests, and security-negative tests.
6. Update docs/contracts and mark the task complete **only after evidence exists**.
7. Report what changed, exact commands/tests and results, limitations and next task.

## Coding-agent boundaries

- Do not auto-deploy to public networks, spend money, publish private telemetry, or provision external services.
- Do not invent benchmark figures, device attestation, regulatory approval, or security properties.
- Use mature maintained crypto libraries; never implement Ed25519, X25519, HKDF or AES-GCM primitives yourself.
- Request explicit human approval before changing ownership rules, encryption design, public API, schema migrations, key custody or blockchain deployment target.
- Use UTC timestamps, stable IDs and documented structured error codes.
- A frontend feature is incomplete if its backend permission enforcement is missing.

## Parallel work and ownership

- **Agent A — Gateway/AI:** `apps/gateway/`, `apps/simulator/`, backend tests.
- **Agent B — Smart contracts:** `packages/contracts/`, contract tests and deployment scripts.
- **Agent C — Web UI:** `apps/web/`, web tests; use `docs/API.md` mocks until backend ready.
- **Agent D — Integration/QA:** `tests/`, `infra/`, docs and reproducible demo.

For a solo developer, use this division as workstreams, not separate personnel. Before concurrent work, agree on `docs/API.md` and `docs/DATA_MODEL.md`. Shared docs may only be changed by a coordinated contract update.

## Done means demonstrated

At least: valid publish; tampered and replayed publish rejected; owner detail view; encrypted insight delivered only to allowed recipient; wrong scope/expired permission denied; revocation prevents **new** deliveries; chain outage fails closed; no private fields exposed; and an end-to-end demo reproducible from documented commands. See `docs/TESTING.md`.
