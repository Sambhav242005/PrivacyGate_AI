# DECISIONS.md — Architecture Decision Records (ADRs)

> Records below are **initial project decisions**, not conclusions from completed field experiments. Modify decisions by adding a superseding ADR; do not silently change past rationale.

## ADR-001 — One vertical-slice demo, not a general decentralized network

- **Status:** Accepted for MVP.
- **Decision:** One simulated industrial machine, one owner, one restricted third-party subscriber, one anomaly type.
- **Rationale:** Clearly proves end-to-end selective disclosure while keeping implementation testable by a solo developer.
- **Rejected:** Multi-device discovery, cross-chain interoperability, open marketplace/payments.
- **Trade-off:** Less representative of a large-scale IoT network.

## ADR-002 — Blockchain = shared authorization registry, not telemetry transport

- **Status:** Accepted.
- **Decision:** Solidity `PermissionRegistry` on local Anvil stores owner, reader, policy SHA-256 digest, expiry, active state and monotonic version. MQTT/HTTP carry off-chain data.
- **Rationale:** Chain throughput and transaction costs should not impact every 1 Hz sensor sample; authorization history can be inspected independently in a future deployed chain.
- **Rejected:** On-chain raw readings, event ciphertext, fully decentralized streaming.
- **Trade-off:** Local gateway remains trusted; Anvil is not decentralized consensus.

## ADR-003 — Local AI generates suggestions, deterministic layer enforces release

- **Status:** Accepted.
- **Decision:** CPU scikit-learn Isolation Forest for anomaly candidacy, rule baseline, fixed event payload. Policy filters are entirely deterministic.
- **Rationale:** AI is useful in interpreting data but cannot be a security decision-maker.
- **Rejected:** LLM-generated arbitrary SQL, autonomous grants, model free-form messages to subscribers.
- **Trade-off:** Limited AI flexibility; better verifiability and privacy.

## ADR-004 — Separate device signing and owner wallet identity

- **Status:** Accepted.
- **Decision:** Device signs telemetry with pinned Ed25519 public key; owner/reader use EVM wallets for permissions and login.
- **Rationale:** Publish rights and grant rights must be separate. A sensor cannot grant access simply because it can upload data.
- **Rejected:** Shared `key_read`/`key_write` passwords for all identities.
- **Trade-off:** More onboarding and rotation complexity.

## ADR-005 — Raw telemetry stays locally encrypted at the application layer

- **Status:** Accepted.
- **Decision:** AES-256-GCM encrypt raw JSON before SQLite storage; private 32-byte key comes from development secret env/key store.
- **Rationale:** Keeps source readings off chain and at least protects payloads in a stolen DB file without the key.
- **Rejected:** Unencrypted raw SQLite columns; claiming full-disk encryption when only fields are encrypted.
- **Trade-off:** Gateway host/key theft still reveals readings; metadata remains visible.

## ADR-006 — Recipient-specific end-to-end envelope encryption

- **Status:** Accepted.
- **Decision:** Reader registers wallet-bound X25519 public key; each delivery uses sender ephemeral X25519, HKDF-SHA256 and AES-GCM with context-bound AAD. Fresh ephemeral keys are generated per recipient/per message; track key epoch on permission changes.
- **Rationale:** Delivery should be confidential to intended subscriber; no shared global insight key.
- **Rejected:** One reusable AES key for all readers; posting plaintext insights to MQTT.
- **Trade-off:** Encryption happens once per authorized recipient; wallet-to-encryption-key binding is an additional attack surface.

## ADR-007 — Confirmed on-chain state and fail-closed disclosure

- **Status:** Accepted.
- **Decision:** Confirmed grant state and local digest both checked before dispatch and retrieval. On RPC failure, deny third-party delivery; no reliance on stale allow-cache as permission to release.
- **Rationale:** Limits permission drift and outage-induced unauthorized disclosure.
- **Rejected:** UI-only checks; permission cache that stays valid indefinitely while disconnected.
- **Trade-off:** Chain outage reduces subscriber availability; frequent RPC reads add latency.

## ADR-008 — No retroactive revocation guarantee

- **Status:** Accepted.
- **Decision:** Once revoke is confirmed and observed, block new and previously queued/unread deliveries for that subscriber; increment key epoch. Previously decrypted/downloading subscriber-held data cannot be recalled.
- **Rationale:** Cryptography and blockchains cannot force deletion from an independent recipient's storage.
- **Rejected:** Marketing claim that revoking consent erases all historical recipient copies.
- **Trade-off:** Absolute post-disclosure privacy is not achievable in this design.

## ADR-009 — API-first and typed schemas

- **Status:** Accepted.
- **Decision:** Pydantic v2/JSON schema and `API.md` are normative; strict request fields; backend exports machine-readable OpenAPI; frontend validates with typed schemas.
- **Rationale:** Avoids backend/frontend mismatch and permission-related bugs introduced by loose types.
- **Rejected:** Frontend reverse-engineering endpoints from backend implementations.
- **Trade-off:** Extra coordination and explicit version updates.

## ADR-010 — Metadata privacy and synthetic data

- **Status:** Accepted.
- **Decision:** Random resource IDs, synthetic wallets and machine readings; only coarse grant data on chain; avoid personal identifiers and VIN/GPS.
- **Rationale:** On-chain metadata and hashes can still be linked; academic demo needs reproducibility, not real personal data.
- **Rejected:** Using real owner/customer identities or publishing actual vehicle traces to public chains.
- **Trade-off:** Synthetic data does not establish real-world predictive value.

## ADR-011 — HTTP pull-based encrypted delivery for MVP

- **Status:** Accepted.
- **Decision:** Third party polls authenticated `/v1/insights`; MQTT used only for sensor↔gateway transport. Each HTTP response returns encrypted envelopes.
- **Rationale:** Easier to validate revocation **again at read time** than a publicly subscribed MQTT output topic.
- **Rejected:** Public encrypted MQTT topic with permanent subscription entitlement.
- **Trade-off:** Not optimized for massive fanout or real-time low-latency delivery; future push protocol would require equivalent authorization.

## ADR-012 — Model output is informational only

- **Status:** Accepted.
- **Decision:** Anomaly classification does not autonomously shut down machines, set insurance rates, or produce definitive safety conclusions.
- **Rationale:** Synthetic fixtures and a small local model cannot justify safety-critical interventions.
- **Rejected:** Autonomous physical actuation in first release.
- **Trade-off:** Narrower field demonstration.

## ADR-013 — Single-owner resource in MVP

- **Status:** Accepted.
- **Decision:** `registerResource(bytes32)` permanently associates a resource with first caller within the demo chain; no transfers or recovery paths in MVP.
- **Rationale:** Owner transfer/recovery complicates security guarantees and is not needed for acceptance scenario.
- **Rejected:** Implicit administrative owner reset, contract upgradeability before threat review.
- **Trade-off:** Production would require owner recovery, transfer, secure upgrade and governance design.

## ADR template for additions

```markdown
## ADR-NNN — Short title
- **Status:** Proposed | Accepted | Superseded by ADR-XXX
- **Context:** What changed or what problem arose?
- **Decision:** Exact behavior to implement.
- **Alternatives:** Options considered.
- **Consequences:** Security, privacy, cost, complexity, tests/docs affected.
```
