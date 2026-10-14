# Project-Structure.md — Intended Repository Layout

> This is a **target structure**, not a claim that source files already exist. Do not create empty placeholder files for every path without implementation need.

```text
privacygate-ai/
├── AGENTS.md
├── SPEC.md
├── Project-Structure.md
├── TESTING.md
├── TASKS.md
├── CONVENTIONS.md
├── DESIGN.md
├── API.md
├── DATA_MODEL.md
├── DECISIONS.md
├── MISTAKES.md
├── .env.example
├── .gitignore
├── README.md                         # Quickstart (create during bootstrapping)
├── Makefile / justfile               # Consistent developer commands
├── docker-compose.yml               # Anvil + Mosquitto (local development only)
├── apps/
│   ├── gateway/
│   │   ├── pyproject.toml
│   │   ├── src/privacygate/
│   │   │   ├── main.py               # FastAPI app / lifecycle
│   │   │   ├── config.py             # Validated environment settings
│   │   │   ├── api/
│   │   │   │   ├── auth.py
│   │   │   │   ├── devices.py
│   │   │   │   ├── policies.py
│   │   │   │   ├── insights.py
│   │   │   │   └── audit.py
│   │   │   ├── domain/
│   │   │   │   ├── schemas.py         # Pydantic v2 DTOs/enums
│   │   │   │   └── policy.py          # Pure authorization logic
│   │   │   ├── ingest/
│   │   │   │   ├── mqtt.py
│   │   │   │   └── signatures.py
│   │   │   ├── ai/
│   │   │   │   ├── inference.py
│   │   │   │   ├── baseline.py
│   │   │   │   └── training.py
│   │   │   ├── security/
│   │   │   │   ├── wallet_auth.py
│   │   │   │   ├── envelopes.py
│   │   │   │   └── crypto_store.py
│   │   │   ├── chain/
│   │   │   │   ├── client.py
│   │   │   │   ├── permissions.py
│   │   │   │   └── sync.py
│   │   │   ├── storage/
│   │   │   │   ├── models.py
│   │   │   │   ├── repository.py
│   │   │   │   └── migrations/
│   │   │   └── services/
│   │   │       ├── event_pipeline.py
│   │   │       └── delivery.py
│   │   └── tests/
│   │       ├── unit/
│   │       └── integration/
│   ├── simulator/
│   │   ├── pyproject.toml
│   │   ├── src/simulator/{main.py,fixtures.py,signing.py}
│   │   └── tests/
│   └── web/
│       ├── package.json
│       ├── src/app/                   # Next.js App Router
│       │   ├── (owner)/dashboard/
│       │   ├── (subscriber)/insights/
│       │   └── login/
│       ├── src/components/
│       ├── src/lib/{api.ts,wallet.ts,schemas.ts}
│       └── tests/
├── packages/
│   ├── contracts/
│   │   ├── foundry.toml
│   │   ├── src/PermissionRegistry.sol
│   │   ├── script/Deploy.s.sol
│   │   └── test/PermissionRegistry.t.sol
│   └── shared/
│       ├── json-schema/              # API/outgoing-insight contract fixtures
│       └── fixtures/                 # Golden canonical JSON examples
├── infra/
│   ├── mosquitto/{mosquitto.conf,acl.conf}
│   ├── anvil/
│   └── scripts/{bootstrap.sh,demo.sh,smoke.sh}
├── tests/
│   ├── e2e/
│   ├── security/
│   └── performance/
├── docs/
│   ├── threat-model.md               # Expand DESIGN threat model as needed
│   └── results/                      # Measurements, environment, screenshots
└── .github/workflows/{backend.yml,contracts.yml,web.yml,e2e.yml}
```

## Folder ownership and import constraints

| Location | Owner | Allowed dependencies |
|---|---|---|
| `apps/simulator` | Publisher | Shared schemas; not gateway internal DB |
| `apps/gateway/domain` | Core policy | Pure Python, schemas; **no FastAPI/chain/DB imports** |
| `apps/gateway/ingest` | Transport/security | Validated domain messages and repository |
| `apps/gateway/ai` | Local inference | Numeric telemetry only; never wallet or key state |
| `apps/gateway/chain` | Blockchain adapter | Contract ABI, RPC; no raw telemetry |
| `apps/gateway/security` | Auth/encryption | Cryptography and key custody interfaces |
| `apps/gateway/api` | HTTP | Calls services; no business logic in route handlers |
| `apps/web` | UI | Typed API and wallet contracts only |
| `packages/contracts` | Authorization registry | Solidity contract, scripts and Foundry tests |
| `packages/shared` | All clients | Published JSON-schema fixtures and stable sample payloads |

## Dependency direction

`API/UI or MQTT -> application services -> pure domain -> infrastructure adapters`. The domain layer must never import adapters. AI cannot call `chain.grant()` or `repository.get_raw_for_subscriber()` directly. Cryptographic operations happen behind testable interfaces.

## Data and environment locations

- SQLite defaults to `./var/privacygate.sqlite3` (ignored by git).
- Trained model artifacts default to `./var/models/` (ignored unless intentionally versioned and documented).
- Development keys and secrets come from environment/secrets files outside git; `.env.example` has blanks and safe non-secret settings.
- Temporary decrypted files must never be written by the web app.
- Chain ABI originates from `packages/contracts` build artifacts and is synchronized into backend/web during build; do not maintain hand-edited copies.

## Build order

1. Shared schemas and contract ABI.
2. Backend service/domain boundaries.
3. Simulator and golden signed telemetry fixture.
4. AI inference and policy engine.
5. Crypto, chain adapter and contract.
6. HTTP interface and web UI.
7. Integrated security tests and documented demonstration.

## Additional files created during implementation

`README.md`, lockfiles (`uv.lock`, `pnpm-lock.yaml`), pinned dependencies, `.gitignore`, Docker files, migrations, seed fixtures and CI jobs should be generated when their corresponding components are implemented. All must remain consistent with the interfaces specified here.
