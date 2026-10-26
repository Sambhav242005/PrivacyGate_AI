[CmdletBinding()]
param([switch]$ConfirmReset)
$ErrorActionPreference = 'Stop'
if (!$ConfirmReset) { throw 'Destructive reset requires -ConfirmReset; all v2 demo keys and data will be deleted' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$expected = [IO.Path]::GetFullPath((Join-Path $repo 'var/v2'))
& (Join-Path $PSScriptRoot 'Stop.ps1')
if (Test-Path -LiteralPath $expected) {
    $resolved = (Resolve-Path -LiteralPath $expected).Path
    $item = Get-Item -LiteralPath $expected -Force
    if ($resolved -ne $expected -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe reset path or junction; refusing deletion' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Host 'Deleted v2 runtime only. Legacy data preserved. Run Setup.ps1 to reprovision.'
