#!/usr/bin/env bash
# PG-042 smoke: fast offline gates. Windows: run via WSL2 (bash ./infra/scripts/smoke.sh)
# or the equivalent commands in PowerShell (see docs/results/README.md).
set -euo pipefail
cd "$(dirname "$0")/../.."
python -m pytest apps/gateway/tests -q
python -m pytest tests/e2e -q
echo "smoke OK"
