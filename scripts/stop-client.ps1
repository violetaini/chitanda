$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $projectRoot "run\client.pid"
$expectedExe = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "bin\myxray-client.exe"))

if (-not (Test-Path -LiteralPath $pidFile)) {
    Write-Host "MyXray client is not running."
    exit 0
}

$clientPid = [int](Get-Content -LiteralPath $pidFile -Raw).Trim()
$process = Get-Process -Id $clientPid -ErrorAction SilentlyContinue
if ($null -eq $process) {
    Remove-Item -LiteralPath $pidFile -Force
    Write-Host "Removed a stale MyXray PID file."
    exit 0
}
if ($process.ProcessName -ne "myxray-client" -or $process.Path -ne $expectedExe) {
    throw "PID $clientPid does not belong to this MyXray client; it was not stopped."
}

Stop-Process -Id $clientPid
Remove-Item -LiteralPath $pidFile -Force
Write-Host "MyXray client stopped."
