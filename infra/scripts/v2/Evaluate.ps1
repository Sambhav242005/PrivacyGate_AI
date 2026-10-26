[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
Push-Location $repo
try {
    & uv run --locked python infra/scripts/v2/evaluate.py
    if ($LASTEXITCODE -ne 0) { throw 'Evaluation failed' }
} finally { Pop-Location }
