# Five-minute native demonstration

Use synthetic accounts/data only. The setup generates unique passwords and keys
under the protected, ignored `var/v2` directory. Do not include that directory in
submission archives. The application never needs a wallet, real MQTT, or external
blockchain service.

## Prepare

From the repository root in Windows PowerShell:

```powershell
./infra/scripts/v2/Setup.ps1
./infra/scripts/v2/Start.ps1 -Production
```

Open http://127.0.0.1:3000. Read the generated passwords locally from
`var/v2/credentials.json`. If those ports are occupied, use:

```powershell
./infra/scripts/v2/Start.ps1 -Production -WebPort 3001 -GatewayPort 8001
$env:PG_WEB_URL = 'http://127.0.0.1:3001'
```

Do not stop unrelated applications to free ports. The current port choice is
saved into v2 config, and the frontend build receives the matching gateway URL.

## Walkthrough

| Time | Action and evidence |
|---|---|
| 0:00–0:40 | Explain the network overview is illustrative. One validator records signed permission transactions; no telemetry goes on-chain. |
| 0:40–1:30 | Owner login, add synthetic equipment, show its registration receipt. Run normal then tampered simulation. Show accepted/rejected counts and owner-only readings. |
| 1:30–2:20 | Grant reader access and inspect the committed block receipt. Sign in as reader, create a key, download/acknowledge backup, register only the public key. |
| 2:20–3:20 | Owner emits an anomaly. Reader restores backup, requests equipment insights, decrypts in browser. Compare five-field insight with owner numeric readings. |
| 3:20–4:10 | Owner revokes. Reader refresh is denied. Explain previously obtained copies cannot be recalled. |
| 4:10–5:00 | Show dated test/model/benchmark evidence. Explain synthetic metrics, trusted gateway key custody, centralized validator and metadata limits. |

## Reusable UI recording

The retained Playwright scripts discover actual fields, rehearse all selectors,
and then record a 1280×720 WebM with a visible cursor and subtitles:

```powershell
# Set this only for non-default web port:
# $env:PG_WEB_URL = 'http://127.0.0.1:3001'
node apps/web/e2e/v2-demo.cjs --discover
node apps/web/e2e/v2-demo.cjs --rehearse
node apps/web/e2e/v2-demo.cjs --record
```

Output: `docs/results/demo-privacygate-v2.webm`. Discovery produces
`docs/results/v2-fieldmap.json`. Rehearsal proof and reader2 recovery backup stay
in protected `var/v2`; the latter contains a plaintext private key and must never
be shared. Repeated recordings restore this same key rather than silently
rotating it. If reader2 was independently enrolled without this backup, the
script stops with an explicit recovery instruction.

Scripts fail on selector errors and require a matching successful rehearsal
before recording. They do not weaken login throttling; wait for the documented
five-minute login window if repeated manual runs exhaust it.

## Verify and stop

```powershell
./infra/scripts/v2/Smoke.ps1
# With the stack running, separately run the required real browser gate:
Push-Location apps/web
npx.cmd playwright test e2e/v2.spec.ts --reporter=line
Pop-Location
./infra/scripts/v2/Evaluate.ps1
uv run --locked python infra/scripts/v2/benchmark.py
./infra/scripts/v2/Stop.ps1
```

`Smoke.ps1` builds the frontend; stop any dev server before this build. Its
`-IncludeBrowser` option requires an already-running compatible stack. CI runs
the build and browser stages separately. Remote CI execution is separate from
locally recorded evidence.

`Reset.ps1 -ConfirmReset` explicitly destroys only v2 state, credentials and keys.
It is unnecessary for ordinary startup. Setup preserves an existing runtime.
