[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProcessIdentity.ps1')
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$recordPath = Join-Path $repo 'var/v2/processes.json'
if (!(Test-Path -LiteralPath $recordPath)) { Write-Host 'No recorded v2 processes'; return }
$records = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
foreach ($record in $records) {
    $proc = Get-Process -Id $record.id -ErrorAction SilentlyContinue
    if ($proc -and (Test-RecordedProcessIdentity -Process $proc -RecordedStart $record.start_time)) {
        Stop-Process -Id $proc.Id
    } elseif ($proc) { throw "PID was reused; refusing to stop unrelated process $($record.id)" }
}
Remove-Item -LiteralPath $recordPath
Write-Host 'Stopped recorded v2 processes'
