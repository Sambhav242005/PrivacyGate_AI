[CmdletBinding()]
param([switch]$IncludeBrowser)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
Push-Location $repo
try {
    & uv run --locked ruff check apps/gateway/src/privacygate_v2 apps/gateway/tests/v2 infra/scripts/v2 tests/v2
    if ($LASTEXITCODE -ne 0) { throw 'Python lint failed' }
    & uv run --locked ruff format --check apps/gateway/src/privacygate_v2 apps/gateway/tests/v2 infra/scripts/v2 tests/v2
    if ($LASTEXITCODE -ne 0) { throw 'Python formatting failed' }
    & uv run --locked mypy apps/gateway/src/privacygate_v2
    if ($LASTEXITCODE -ne 0) { throw 'Python type checks failed' }
    & uv run --locked pytest apps/gateway/tests/v2 tests/v2 -q
    if ($LASTEXITCODE -ne 0) { throw 'Python acceptance tests failed' }
    Push-Location apps/web
    try {
        foreach ($check in @('tsc','lint','test','build')) {
            & npm.cmd run $check
            if ($LASTEXITCODE -ne 0) { throw "Web $check failed" }
        }
        if ($IncludeBrowser) {
            & npx.cmd playwright test e2e/v2.spec.ts --reporter=line
            if ($LASTEXITCODE -ne 0) { throw 'Real browser acceptance failed' }
        }
    } finally { Pop-Location }
} finally { Pop-Location }
