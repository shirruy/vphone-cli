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
Write-Host " VPHONE WINDOWS PORT - PHASE 0-2 CUMULATIVE VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/02-backend-boundary") {
    throw "VALIDATION FAIL: expected branch phase/02-backend-boundary, found '$branch'"
}

if (git status --porcelain) {
    throw "VALIDATION FAIL: working tree is not clean before validation."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

Invoke-Checked -Label "[1/6] Phase 0 Windows environment preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

$evidenceDir = Join-Path (Get-Location) "build\phase2-revalidation-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[2/6] Phase 1 full compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase2\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "VALIDATION FAIL: census has unclassified compile units. unknown=$($census.unknown_count)"
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "VALIDATION FAIL: Phase 2 compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE", "SHIMMABLE", "REWRITE", "APPLE_ONLY")) {
    $runtimeCount = $census.categories.$category
    $baselineCount = $baseline.categories.$category
    if ($runtimeCount -ne $baselineCount) {
        throw "VALIDATION FAIL: Phase 2 category drift for $category. runtime=$runtimeCount, baseline=$baselineCount"
    }
}

Invoke-Checked -Label "[3/6] Configure Windows Phase 2 build" -Action {
    if (Test-Path ".\build\windows-phase2") {
        Remove-Item ".\build\windows-phase2" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase2"
}

Invoke-Checked -Label "[4/6] Build Windows targets" -Action {
    cmake --build ".\build\windows-phase2" --config Release
}

Invoke-Checked -Label "[5/6] Execute Release-mode native contract suite" -Action {
    ctest --test-dir ".\build\windows-phase2" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/6] Validate shared protocol v1 fixture through Windows CLI" -ForegroundColor Yellow

$exe = Get-ChildItem ".\build\windows-phase2" -Filter "vphone-vm-win.exe" -File -Recurse |
    Select-Object -First 1
if (-not $exe) {
    throw "VALIDATION FAIL: vphone-vm-win.exe was not produced."
}

$version = (& $exe.FullName protocol-version).Trim()
if ($LASTEXITCODE -ne 0 -or $version -ne "1") {
    throw "VALIDATION FAIL: expected protocol version 1, got '$version'"
}

$fixture = Resolve-Path ".\protocol\fixtures\backend_request_v1_boot.json"
$canonical = & $exe.FullName validate-request $fixture
if ($LASTEXITCODE -ne 0) {
    throw "VALIDATION FAIL: Windows CLI rejected canonical v1 fixture."
}

$parsed = ($canonical -join [Environment]::NewLine) | ConvertFrom-Json
if ($parsed.protocol_version -ne 1) {
    throw "VALIDATION FAIL: protocol_version drifted."
}
if ($parsed.operation -ne "boot") {
    throw "VALIDATION FAIL: operation drifted."
}
if ($parsed.boot.config -ne "/tmp/vphone/demo/config.plist") {
    throw "VALIDATION FAIL: boot.config drifted."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 0-2 WINDOWS REVALIDATION PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units    : $($census.compile_units)"
Write-Host "Unknown          : $($census.unknown_count)"
Write-Host "Protocol version : $version"
Write-Host "Fixture          : $fixture"
Write-Host ""
Write-Host "This restores Windows-side evidence for Phase 0 and Phase 1 and validates the Phase 2 Windows contract."
Write-Host "Full Phase 2 closure still requires the macOS Swift protocol CI job to pass on this same commit."
