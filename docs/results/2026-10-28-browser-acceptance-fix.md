# Browser acceptance repair ? PG-V2-006

Base: 4cfe5a052859495698cc271c8a5d0df13c1b3d20, Windows, Python 3.12.13, Node 24.14.1.
Changes are uncommitted local work. No API, persistence, crypto or ownership contract changed.

## Evidence

- Original unmodified production journey failed locally at the tampered-envelope assertion: no error alert appeared after clicking an existing Open insight button before the refresh response applied.
- After synchronizing inbox replacement, three repetitions exposed a separate wrong-resource denial. A delayed initial dashboard refresh captured empty selection and selected older equipment after registration.
- Added e2e/workspace.spec.ts before the dashboard fix. It failed: Expected Selected, Received Select.
- Fixed refresh by preserving current state with a functional setter and ignoring superseded refreshes. Stable callback avoids re-running session restoration on every resource change.
- Fresh-context sign-in now asserts HTTP 401 from /v2/me within 15 seconds before expecting the form and the role destination. It no longer races two pending locator waits.
- Tampered inbox tests clear the old inbox and wait for newly loaded buttons; injected 250 ms response latency exercises the synchronization boundary, rather than delaying assertions.

## Passing commands

`./infra/scripts/v2/Smoke.ps1`: Ruff checks and formatting, mypy, 43 Python tests (one existing deprecation warning), TypeScript, ESLint, 6 web tests and production build passed.

In PowerShell 7, startup and test execution shared a single shell:

```powershell
try {
  ./infra/scripts/v2/Start.ps1 -Production
  Push-Location apps/web
  try {
    npx.cmd playwright test e2e/v2.spec.ts e2e/workspace.spec.ts --reporter=line --repeat-each=3 --workers=1
    if ($LASTEXITCODE -ne 0) { throw 'Browser acceptance failed' }
  } finally { Pop-Location }
} finally { ./infra/scripts/v2/Stop.ps1 }
```

Final result: 6 passed in 14.7 seconds. This includes three real signed simulation/grant/decrypt/tamper/revoke journeys and three delayed-refresh regression runs. `git diff --check` passed.

## Limits

The original reader-login timeout in Actions run 40644109637 has not been independently reproduced under the same CI conditions. One intermediate local verification overlapped a rebuild with the running production server, invalidating browser assets and causing a session-response timeout; it was discarded and the final run was sequential. This is not evidence for the cause of the remote timeout.

No remote CI run of these edits has occurred. The workflow and Smoke browser command now include the regression test. No public artifacts containing credentials, private keys, traces or owner readings were uploaded.
