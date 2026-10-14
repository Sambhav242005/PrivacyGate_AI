# docs/results — evidence, not claims

T-01..T-24 are **requirements** (docs/TESTING.md), not passes. Record each run
as `docs/results/YYYY-MM-DD-<run-id>.md` with git SHA, OS/Python/Node/Foundry
versions, Anvil chain ID, seed, model hash, commands, redacted log excerpt,
per-case pass/fail, and known limitations.

## How to run

```bash
# offline rig (no Anvil/MQTT needed; live test skips if unreachable)
python -m pytest tests/e2e -q
# full offline gates
python -m pytest apps/gateway/tests tests/e2e -q
# one-command smoke / demo (Windows: WSL2 bash, or PowerShell equivalents below)
./infra/scripts/smoke.sh
./infra/scripts/demo.sh
```

PowerShell equivalents:

```powershell
python -m pytest apps/gateway/tests -q
python -m pytest tests/e2e -q
```

## Environment table (fill per run)

| Item | Value |
|---|---|
| git SHA | TBD |
| OS / Python / Node / Foundry | TBD |
| Anvil chain ID / contract address | TBD (local 31337 expected) |
| Seed / model version + hash | TBD |
| Commands run | TBD |
| Result (T-01..T-24) | TBD |

## Benchmarks

See BENCHMARKS.md. No invented numbers: leave TBD until measured.
