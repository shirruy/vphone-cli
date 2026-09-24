param()

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    Write-Host ""
    Write-Host $Label -ForegroundColor Yellow
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

Set-Location (Resolve-Path (Join-Path $PSScriptRoot ".."))

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VPHONE WINDOWS PORT - PHASE 2 VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/02-backend-boundary") {
    throw "PHASE 2 FAIL: expected branch phase/02-backend-boundary, found '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 2 FAIL: working tree is not clean before validation."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

Invoke-Checked -Label "[1/4] Configure Windows protocol build" -Action {
    if (Test-Path ".\build\windows-phase2") {
        Remove-Item ".\build\windows-phase2" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase2"
}

Invoke-Checked -Label "[2/4] Build Windows protocol targets" -Action {
    cmake --build ".\build\windows-phase2" --config Release
}

Invoke-Checked -Label "[3/4] Execute Windows protocol contract suite" -Action {
    ctest --test-dir ".\build\windows-phase2" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[4/4] Validate shared v1 fixture through Windows CLI" -ForegroundColor Yellow

$exe = Get-ChildItem ".\build\windows-phase2" -Filter "vphone-vm-win.exe" -File -Recurse |
    Select-Object -First 1
if (-not $exe) {
    throw "PHASE 2 FAIL: vphone-vm-win.exe was not produced."
}

$version = (& $exe.FullName protocol-version).Trim()
if ($LASTEXITCODE -ne 0 -or $version -ne "1") {
    throw "PHASE 2 FAIL: expected protocol version 1, got '$version'"
}

$fixture = Resolve-Path ".\protocol\fixtures\backend_request_v1_boot.json"
$canonical = & $exe.FullName validate-request $fixture
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 2 FAIL: Windows CLI rejected canonical v1 fixture."
}

$parsed = ($canonical -join [Environment]::NewLine) | ConvertFrom-Json
if ($parsed.protocol_version -ne 1) {
    throw "PHASE 2 FAIL: canonical response protocol_version drifted."
}
if ($parsed.operation -ne "boot") {
    throw "PHASE 2 FAIL: canonical response operation drifted."
}
if ($parsed.boot.config -ne "/tmp/vphone/demo/config.plist") {
    throw "PHASE 2 FAIL: canonical response config drifted."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 2 WINDOWS CONTRACT PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Protocol version : $version"
Write-Host "Fixture          : $fixture"
Write-Host ""
Write-Host "NOTE: Full Phase 2 closure still requires the macOS Swift protocol tests to pass in CI."
