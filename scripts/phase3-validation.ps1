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
Write-Host " VPHONE WINDOWS PORT - PHASE 3 VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/03-native-windows-cli") {
    throw "PHASE 3 FAIL: expected phase/03-native-windows-cli, found '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 3 FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase3-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/6] Phase 0 Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/6] Phase 3 compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase3\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 3 FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 3 FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE", "SHIMMABLE", "REWRITE", "APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 3 FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/6] Configure native Windows CLI build" -Action {
    if (Test-Path ".\build\windows-phase3") {
        Remove-Item ".\build\windows-phase3" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase3"
}

Invoke-Checked -Label "[4/6] Build native Windows CLI targets" -Action {
    cmake --build ".\build\windows-phase3" --config Release
}

Invoke-Checked -Label "[5/6] Execute complete Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase3" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/6] Validate native CLI Protocol v1 dry-run parity" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase3" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1

if (-not $cli) {
    throw "PHASE 3 FAIL: vphone-cli-win.exe was not produced."
}

$json = & $cli.FullName vm launch --config "/tmp/vphone/demo/config.plist" --headless --api-listen "127.0.0.1:8765" --kernel-debug-port 62000 --dry-run

if ($LASTEXITCODE -ne 0) {
    throw "PHASE 3 FAIL: native CLI dry-run failed."
}

$request = ($json -join [Environment]::NewLine) | ConvertFrom-Json

if ($request.protocol_version -ne 1) { throw "PHASE 3 FAIL: protocol_version drift." }
if ($request.operation -ne "boot") { throw "PHASE 3 FAIL: operation drift." }
if ($request.boot.config -ne "/tmp/vphone/demo/config.plist") { throw "PHASE 3 FAIL: config drift." }
if (-not $request.boot.headless) { throw "PHASE 3 FAIL: headless flag was not preserved." }
if ($request.boot.api_listen -ne "127.0.0.1:8765") { throw "PHASE 3 FAIL: api_listen drift." }
if ($request.boot.kernel_debug_port -ne 62000) { throw "PHASE 3 FAIL: kernel_debug_port drift." }

$bad = & $cli.FullName vm launch --config "/tmp/test.plist" --dfu --api-listen "127.0.0.1:8765" --dry-run 2>&1
$badExit = $LASTEXITCODE

if ($badExit -eq 0) {
    throw "PHASE 3 FAIL: invalid DFU/API combination unexpectedly succeeded."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 3 WINDOWS CLI VALIDATION PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units : $($census.compile_units)"
Write-Host "Unknown       : $($census.unknown_count)"
Write-Host "CLI           : $($cli.FullName)"
Write-Host "Protocol      : 1"
Write-Host ""
Write-Host "This proves native Windows CLI/core request orchestration only."
Write-Host "It does NOT prove ARM/iOS VM boot."
