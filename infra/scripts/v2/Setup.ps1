[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$env:NEXT_TELEMETRY_DISABLED = '1'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
Push-Location $repo
try {
    & uv sync --locked --python 3.12
    if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed' }
    & ./.venv/Scripts/python.exe infra/scripts/v2/bootstrap.py
    if ($LASTEXITCODE -ne 0) { throw 'Runtime provisioning failed' }
    Push-Location apps/web
    try {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'Web dependency installation failed' }
        & npx.cmd playwright install chromium
        if ($LASTEXITCODE -ne 0) { throw 'Chromium installation failed' }
    } finally { Pop-Location }
} finally { Pop-Location }
