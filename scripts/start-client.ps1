param(
    [string]$Listen = "127.0.0.1:2080",
    [string]$Server = "23.145.248.44:11322",
    [string]$ServerName = "probe.chitanda.org"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$runDir = Join-Path $projectRoot "run"
$exe = Join-Path $projectRoot "bin\myxray-client.exe"
$pskFile = Join-Path $projectRoot "secrets\psk"
$pathFile = Join-Path $projectRoot "secrets\path"
$pidFile = Join-Path $runDir "client.pid"

foreach ($required in @($exe, $pskFile, $pathFile)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required file is missing: $required"
    }
}

if (Test-Path -LiteralPath $pidFile) {
    $oldPid = [int](Get-Content -LiteralPath $pidFile -Raw).Trim()
    $oldProcess = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
    if ($null -ne $oldProcess -and $oldProcess.ProcessName -eq "myxray-client") {
        Write-Host "MyXray client is already running (PID $oldPid)."
        exit 0
    }
}

New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$arguments = @(
    "-listen", $Listen,
    "-server", $Server,
    "-server-name", $ServerName,
    "-psk-file", $pskFile,
    "-path-file", $pathFile
)
$process = Start-Process `
    -FilePath $exe `
    -ArgumentList $arguments `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $runDir "client.stdout.log") `
    -RedirectStandardError (Join-Path $runDir "client.stderr.log") `
    -PassThru

Set-Content -LiteralPath $pidFile -Value $process.Id
Write-Host "MyXray client started on $Listen (PID $($process.Id))."
