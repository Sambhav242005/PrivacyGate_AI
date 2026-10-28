# PG-V2-007 — reviewed learning implementation checkpoint

Date: 2026-10-28. Base commit: `83f8b45`. Windows, Python 3.12.

Implemented owner-scoped local batch retraining, separate labeled validation,
incumbent/rule comparisons, promotion gates, encrypted resource-specific recipes,
model versions, expiry, restart loading and rollback. See [LEARNING.md](../LEARNING.md).

Executed checks:

- Cached Ruff 0.17.0 `check` over v2 gateway source/tests and v2 scripts/tests:
  passed.
- Cached Ruff 0.17.0 `format --check` over the same paths: 22 files formatted.
- `.venv/Scripts/python.exe -m compileall -q apps/gateway/src/privacygate_v2 apps/gateway/tests/v2 infra/scripts/v2`:
  passed.
- `git diff --check`: passed.

Full pytest, locked Ruff and mypy execution are **pending**. Dependency downloads
did not finish before the user requested this checkpoint be committed and pushed.
No retraining metrics or runtime success are claimed. PG-V2-007 remains unchecked
until its acceptance tests pass. Run the commands in [TESTING.md](../TESTING.md)
after dependencies are available; address any failures before activating a model.

Tests added cover seeded distribution shift, invalid reviews, non-improving
activation, encrypted artifact integrity, expiry, contention, dependency mismatch,
CLI evaluation/activation/rollback, and gateway authorization after model loading.
These tests have not yet executed. No model was activated in the local demo.
