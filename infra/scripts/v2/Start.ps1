[CmdletBinding()]
param(
    [switch]$Production,
    [ValidateRange(1024,65535)][int]$GatewayPort = 8000,
    [ValidateRange(1024,65535)][int]$ValidatorPort = 8010,
    [ValidateRange(1024,65535)][int]$WebPort = 3000
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$runtime = Join-Path $repo 'var/v2'
$python = Join-Path $repo '.venv/Scripts/python.exe'
if (!(Test-Path -LiteralPath (Join-Path $runtime 'config.json'))) { throw 'Run Setup.ps1 first' }
if (Test-Path -LiteralPath (Join-Path $runtime 'processes.json')) { throw 'Recorded processes exist; run Stop.ps1 before starting' }
if (@($GatewayPort,$ValidatorPort,$WebPort | Select-Object -Unique).Count -ne 3) { throw 'Service ports must differ' }
foreach ($port in @($GatewayPort,$ValidatorPort,$WebPort)) {
    $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
    if ($listener) { throw "Port $port is already in use; stop its owner first" }
}
$configPath = Join-Path $runtime 'config.json'
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$config.origin = "http://127.0.0.1:$WebPort"
$config.chain.url = "http://127.0.0.1:$ValidatorPort"
$config | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 -LiteralPath $configPath
$env:NEXT_PUBLIC_GATEWAY_URL = "http://127.0.0.1:$GatewayPort"
$env:NEXT_TELEMETRY_DISABLED = '1'
if ($Production) {
    Push-Location (Join-Path $repo 'apps/web')
    try {
        & npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'Production web build failed' }
    } finally { Pop-Location }
}
$started = @()
function Wait-Ready([string]$url, [System.Diagnostics.Process]$process) {
    for ($i = 0; $i -lt 120; $i++) {
        $process.Refresh()
        if ($process.HasExited) { throw "Service exited before readiness: $url; inspect var/v2 logs" }
        try { $r = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 2; if ($r.StatusCode -eq 200) { return } } catch { }
        Start-Sleep -Milliseconds 500
    }
    throw "Service readiness timed out: $url"
}
try {
    foreach ($service in @('validator','gateway')) {
        $port = if ($service -eq 'validator') { $ValidatorPort } else { $GatewayPort }
        $proc = Start-Process -FilePath $python -ArgumentList @('infra/scripts/v2/serve.py',$service,'--port',"$port") -WorkingDirectory $repo -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtime "$service.out.log") -RedirectStandardError (Join-Path $runtime "$service.err.log") -PassThru
        $started += @{id=$proc.Id;name=$service;start_time=$proc.StartTime.ToUniversalTime().ToString('o')}
        Wait-Ready "http://127.0.0.1:$port/$(if($service -eq 'gateway'){'v2/health'}else{'health'})" $proc
    }
    $node = (Get-Command node.exe).Source
    $webMode = if ($Production) { 'start' } else { 'dev' }
    $proc = Start-Process -FilePath $node -ArgumentList @('node_modules/next/dist/bin/next',$webMode,'--hostname','127.0.0.1','--port',"$WebPort") -WorkingDirectory (Join-Path $repo 'apps/web') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtime 'web.out.log') -RedirectStandardError (Join-Path $runtime 'web.err.log') -PassThru
    $started += @{id=$proc.Id;name='web';start_time=$proc.StartTime.ToUniversalTime().ToString('o')}
    Wait-Ready "http://127.0.0.1:$WebPort" $proc
    $started | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $runtime 'processes.json')
    Write-Host "PrivacyGate v2 ready: http://127.0.0.1:$WebPort"
} catch {
    foreach ($record in $started) { Stop-Process -Id $record.id -ErrorAction SilentlyContinue }
    throw
}
