# PrivacyGate AI

A Windows-native academic MVP: **signed sensor simulation → encrypted storage → local anomaly detection → custom blockchain authorization → recipient-encrypted insight**.

The owner sees detailed readings. A reader receives only an authorized five-field anomaly insight and decrypts it in their browser. Our own single-validator chain records signed permission changes; it never stores telemetry or insight content.

## Run locally

Prerequisites: Windows PowerShell, uv, Node.js 24+/npm. Setup installs the locked Python 3.12 environment, web dependencies, and Playwright Chromium.

```powershell
./infra/scripts/v2/Setup.ps1
./infra/scripts/v2/Start.ps1 -Production
```

Open **http://127.0.0.1:3000**. Local passwords for `owner`, `reader`, and `reader2` are generated in the protected `var/v2/credentials.json`; do not share this file. No external blockchain, wallet, MQTT broker, Docker, or WSL is required.

If ports are occupied:

```powershell
./infra/scripts/v2/Start.ps1 -Production -WebPort 3001 -GatewayPort 8001
$env:PG_WEB_URL = 'http://127.0.0.1:3001'
```

Setup preserves existing state. All services bind loopback. Stop only the recorded application processes:

```powershell
./infra/scripts/v2/Stop.ps1
```

`Reset.ps1 -ConfirmReset` explicitly deletes v2 data and keys. Legacy databases are never migrated or deleted automatically.

## Demonstrate

1. Owner signs in, adds equipment, runs normal/tampered simulation and inspects readings and registration receipt.
2. Reader creates a viewing key, explicitly saves its local backup, and registers only the public key.
3. Owner grants the reader access and emits an anomaly.
4. Reader enters the equipment reference and decrypts the five-field insight.
5. Owner revokes access; subsequent reader requests are denied.

Keep the reader backup private. Closing a tab or signing out clears its memory key; restore the matching backup to reopen insights.

[Five-minute walkthrough and reusable video script](docs/DEMO_V2.md) · [Architecture](docs/ARCHITECTURE_V2.md) · [Authoritative v2 protocol](docs/V2.md)

## Verify

Stop the dev server before running the build gates:

```powershell
./infra/scripts/v2/Smoke.ps1
./infra/scripts/v2/Start.ps1 -Production
Push-Location apps/web
npx.cmd playwright test e2e/v2.spec.ts --reporter=line
Pop-Location
./infra/scripts/v2/Evaluate.ps1
uv run --locked python infra/scripts/v2/benchmark.py
```

Use the `PG_WEB_URL` override for browser tests when using alternate ports. The required live test fails if credentials/services are absent; mocked UI tests are separately labeled. The native Windows CI workflow repeats setup, checks, production startup and live browser acceptance.

[Execution evidence](docs/results/2026-10-26-v2-completion.md) records actual commands, results, benchmark boundaries and limitations. CI configuration is not proof that remote CI ran. Older v1 tests/docs are historical and superseded by docs/V2.md.

## Trust and limitations

- Single-validator chain: centralized authority, not distributed consensus.
- Trusted gateway holds owner signing keys and raw data in memory; host compromise defeats that boundary.
- Raw payload encryption does not hide SQLite metadata or encrypt the entire file.
- Revocation blocks future release, not previously received copies or already-authorized responses in flight.
- Reader private keys are not uploaded or stored in browser storage. User-requested backups are plaintext secrets.
- Model evaluation uses synthetic, deliberately separated distributions. The rule baseline outperforms Isolation Forest on this holdout; neither establishes real equipment accuracy.
- Valid-prefix rollback detection requires a retained checkpoint. Compromised validator keys and rewritten checkpoints are outside the trust model.
- One gateway worker is supported. No production certification or public deployment is claimed.
