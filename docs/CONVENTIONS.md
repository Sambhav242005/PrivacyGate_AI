# CONVENTIONS.md — Engineering, Naming and Security Rules

## 1. Language/tooling choices

| Area | Convention |
|---|---|
| Gateway, simulator and scripts | Python 3.11+; `ruff`, `mypy`, `pytest`, `uv`; Pydantic v2, FastAPI, SQLAlchemy + Alembic |
| AI | scikit-learn on CPU; separate deterministic baseline; pinned model artifact/version |
| Contracts | Solidity ^0.8.24; Foundry (`forge`, `anvil`, scripts); explicit ABI artifacts |
| Frontend | TypeScript strict, Next.js App Router, React, Zod, Vitest/Playwright, pnpm |
| Docker | Local Mosquitto and Anvil; bind sensitive dev ports to loopback |
| Crypto | `cryptography` maintained library; Ed25519, X25519, HKDF-SHA256, AES-256-GCM |
| Database | SQLite with AES-GCM encrypted telemetry *payload columns*, not a claim of whole-database encryption |

Pin working versions in lockfiles. Avoid unsupported speculative package versions.

## 2. Naming and formatting

- Python modules, fields and SQL columns: `snake_case`; Python classes: `PascalCase`; constants: `UPPER_SNAKE_CASE`.
- TypeScript variables/functions: `camelCase`; React components/types: `PascalCase`; EVM wallet/address bytes presented as `0x...` when external.
- Solidity functions and variables: `camelCase`; events: `PascalCase`; errors: `PascalCase`; immutable/read-only ownership controls.
- URLs: plural REST nouns under `/v1`, kebab-case path segments when multiword. Request/response JSON keys **always `snake_case`**, including frontend DTOs.
- Identifiers: `resource_id` is a random 32-byte hex string with `0x` prefix on chain and HTTP. `device_id`, `policy_id`, `event_id`, `delivery_id` are UUIDv4 canonical strings. Wallets normalized to checksum representation for display, compared as 20-byte addresses.
- Time: UTC `YYYY-MM-DDTHH:mm:ss.sssZ` in HTTP; Unix seconds (`uint64`) on-chain. No implicit local timezone.
- Value units: `temp_c` Celsius; `vibration_mm_s` millimeters/second; `rpm` revolutions/minute; documented reasonable ranges.
- Markdown: keep docs in repo root per requested filenames; update relevant docs in same PR when changing behavior.

## 3. Responses and errors

- Success is JSON with explicit schema. Pagination uses opaque `next_cursor` and stable sort ordering.
- Errors follow `{ "error": { "code": "POLICY_DENIED", "message": "Access not allowed", "request_id": "..." } }`.
- Expose no keys, secret claims, raw telemetry values, untrusted model content or stack traces in production error responses.
- Standard HTTP: `400` malformed, `401` unauthenticated, `403` denied, `404` unknown or intentionally masked resource, `409` conflict/replay, `422` schema invalid, `429` rate limit, `503` chain state unavailable. See `API.md`.

## 4. Secure-by-default implementation

1. Validate all untrusted JSON at boundaries with explicit schema and forbidden extra fields unless a *local-only* internal schema intentionally allows them.
2. Use Ed25519 signatures over canonicalized unsigned sensor fields; verify resource/device binding and monotonic sequence within one DB transaction.
3. Never use `pickle` or dynamic code loading on user inputs; treat model artifacts as trusted build artifacts only.
4. AI emits **structured candidate insights**; deterministic code validates event type, recipient, owner policy and exact allowed five-field payload. Never use model-generated SQL.
5. Authenticate wallets via one-time challenge bound to domain, wallet, chain ID, timestamp, nonce and audience; sign using standard EIP-191 personal-sign. Restrict origin and add CSRF protection to cookie-authenticated mutation endpoints.
6. Generate cryptographic randomness with OS CSPRNG. Per-envelope ephemeral X25519 plus HKDF and AES-GCM; authenticate relevant context as AAD. Unique random 96-bit nonce for each independent fresh derived AES key.
7. Any third-party release requires confirmed on-chain permission AND exact local policy digest. On RPC/verification failure, return `503 AUTHZ_UNAVAILABLE`, with **zero plaintext or ciphertext disclosed**.
8. SQLite writes of raw JSON use AES-GCM encrypted BLOB plus separate nonce; log device ID/sequence/status only. Backup/decrypt keys separately and do not upload local databases.
9. Use TLS for non-loopback HTTP and MQTT transports. Localhost HTTP/plain MQTT is a constrained development assumption, not production guidance.
10. Contract wallet addresses, grants and digests can reveal metadata; only synthetic wallets/resources in demonstration.

## 5. Canonical JSON and digests

- Canonical JSON uses UTF-8, lexicographically sorted keys, no whitespace, ASCII escaping disabled, normalized strings, finite numeric values; **no floats in signed policy manifests** (use integer timestamps and symbolic enums). Reuse canonical-golden fixtures under `packages/shared/fixtures` across languages.
- Device signature: Ed25519 over canonical JSON of message envelope **excluding** `signature_b64`.
- Policy digest: `SHA256(canonical_policy_json)` as 32 bytes (`0x` + 64 hex); compare directly to confirmed smart-contract bytes32. Contract does not calculate or validate manifest truth.
- For on-chain `resource_id` use 32 CSPRNG bytes, **not** a reversible name, VIN, username, serial or GPS position.
- `policy_revision` is an off-chain positive integer; contract grant `version` is a separate monotonic on-chain counter. Do not conflate them.

## 6. Logging and observability

Logs are structured JSON with `time`, `level`, `service`, `request_id`, `resource_id` (synthetic), `event_code`, `duration_ms`. Log *counts*, states and IDs only; never entire telemetry/signature/key/plaintext envelope. Rate limit auth and delivery endpoints. Correlation IDs may not contain personal data.

## 7. Database and migrations

Use Alembic migrations, explicit SQL constraints and indexes. Avoid mutable global SQLite connections. Save sequence change and accepted telemetry atomically. Use transactions for policy activation and queued-delivery invalidation. Migration must keep already encrypted ciphertext encrypted. Never silently reset the data file on startup.

## 8. Frontend conventions

- Owner and subscriber UI are views, not security boundaries.
- Browser receives only necessary decrypted data; store sessions in HttpOnly secure cookies, and never persist recipient X25519 secret key or session tokens in `localStorage`. For demo, provide in-memory key handling or a user-controlled export with explicit warning.
- Distinguish pending vs confirmed grants/revocations; do not optimistically display "revoked" before chain confirmation/sync.
- Use semantic labels, keyboard navigation, color-independent permission indicators and responsive panels.

## 9. Change management and reviews

- Commit prefixes: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `security:`. Reference `TASKS.md` IDs in PR summary.
- Review checklist: schema change? policy bypass? authorization at both send/read? leakage via errors/logs? replay? SQL injection? expired key? cross-browser wallet? chain outage? test coverage? docs updated?
- Never mark tasks complete based only on screenshots or unit tests that mock out the critical security check.
