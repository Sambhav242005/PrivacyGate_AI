#!/usr/bin/env bash
# PG-045 demo walkthrough (5 min). Windows: run via WSL2; PowerShell equivalents
# in docs/results/README.md. Live steps skip gracefully when Anvil/MQTT/web are down.
set -euo pipefail
cd "$(dirname "$0")/../.."
echo "== 1/4 unit + e2e =="
python -m pytest apps/gateway/tests tests/e2e -q
echo "== 2/4 contracts (needs Foundry) =="
if command -v forge >/dev/null 2>&1 && [ -d packages/contracts ]; then
  (cd packages/contracts && forge test -vv) || echo "contract tests FAILED (see output)"
else
  echo "SKIP: forge or packages/contracts unavailable"
fi
echo "== 3/4 web build (needs pnpm) =="
if command -v pnpm >/dev/null 2>&1 && [ -d apps/web ]; then
  (cd apps/web && pnpm build) || echo "web build FAILED (see output)"
else
  echo "SKIP: pnpm or apps/web unavailable"
fi
echo "== 4/4 live services (optional) =="
python -m pytest tests/e2e -q -k live_services -rs || true
echo "demo script done; record results under docs/results/"
