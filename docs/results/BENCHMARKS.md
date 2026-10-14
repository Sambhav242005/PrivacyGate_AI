# BENCHMARKS.md — PG-044 skeleton (no invented numbers)

Method per docs/TESTING.md Performance section: measure independently
(MQTT receive→stored, stored→AI, AI→envelope, envelope→HTTP response,
grant confirmation, revoke sync delay). Record p50/p95/p99, count,
environment, CPU, synthetic input rate. Never mix contract-grant time
into per-message delivery. Compare against simple local-ACL variant on
the same hardware/input.

## How to run (once harness lands)

```bash
python -m pytest tests/e2e -q
# future: python infra/scripts/bench.py --rate 1 --seconds 60 --out docs/results/<run-id>.json
```

Windows: WSL2 bash, or the same `python -m pytest` lines in PowerShell.

## Environment

| Item | Value |
|---|---|
| CPU / RAM / OS | TBD |
| Python / Node / Foundry | TBD |
| Input rate / duration / seed | TBD |
| Model version + hash | TBD |

## Results (empty until measured — do NOT invent)

| Stage | n | p50 | p95 | p99 | Notes |
|---|---|---|---|---|---|
| MQTT receive→stored | TBD | TBD | TBD | TBD | local Mosquitto |
| stored→AI | TBD | TBD | TBD | TBD | rule-v1 baseline |
| AI→allowed envelope | TBD | TBD | TBD | TBD | per-recipient encrypt |
| envelope→HTTP response | TBD | TBD | TBD | TBD | subscriber fetch |
| grant confirm delay | TBD | TBD | TBD | TBD | Anvil local |
| revoke sync delay | TBD | TBD | TBD | TBD | poll interval |

Target (aspirational, not guaranteed): p95 <2s at 1 sensor / 1Hz local load.
