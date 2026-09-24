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
Write-Host " VPHONE WINDOWS PORT - PHASE 4C2 COMPRESSION PARITY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04c-compression-bundle-parity") {
    throw "PHASE 4C2 FAIL: expected phase/04c-compression-bundle-parity, found '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4C2 FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4c2-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/6] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/6] Phase 4C2 compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4c2\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4C2 FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4C2 FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE", "SHIMMABLE", "REWRITE", "APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4C2 FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/6] Configure compression parity build" -Action {
    if (Test-Path ".\build\windows-phase4c2") {
        Remove-Item ".\build\windows-phase4c2" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4c2"
}

Invoke-Checked -Label "[4/6] Build compression parity targets" -Action {
    cmake --build ".\build\windows-phase4c2" --config Release
}

Invoke-Checked -Label "[5/6] Execute Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4c2" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/6] Verify compression capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4c2" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4C2 FAIL: vphone-cli-win.exe was not produced."
}

$cap = ((& $cli.FullName archive-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4C2 FAIL: archive-capabilities command failed."
}

foreach ($name in @("gzip", "xz", "zstd")) {
    if ($cap.$name -ne "supported") {
        throw "PHASE 4C2 FAIL: $name capability is not supported."
    }
}

if ($cap.bundle_manifest_validation -ne "supported") {
    throw "PHASE 4C2 FAIL: Phase 4C1 bundle validation regressed."
}
if ($cap.windows_hardlink_identity -ne "supported") {
    throw "PHASE 4C2 FAIL: Phase 4C1 hardlink identity regressed."
}
if ($cap.symlink_import -ne "unsupported") {
    throw "PHASE 4C2 FAIL: symlink import must remain unsupported."
}
if ($cap.darwin_xattrs_acl -ne "unsupported") {
    throw "PHASE 4C2 FAIL: Darwin metadata must remain unsupported."
}

$tests = ctest --test-dir ".\build\windows-phase4c2" -C Release -N
$testText = $tests -join [Environment]::NewLine

foreach ($required in @(
    "compression_transport_roundtrip",
    "bundle_manifest_validation",
    "windows_hardlink_identity",
    "archive_gnutar_roundtrip"
)) {
    if ($testText -notmatch $required) {
        throw "PHASE 4C2 FAIL: required test '$required' is not registered."
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4C2 COMPRESSION PARITY PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units : $($census.compile_units)"
Write-Host "Unknown       : $($census.unknown_count)"
Write-Host "gzip          : $($cap.gzip)"
Write-Host "xz            : $($cap.xz)"
Write-Host "zstd          : $($cap.zstd)"
Write-Host "Bundle parity : preserved"
Write-Host ""
Write-Host "Phase 4C is closed when this validator passes on physical Windows and CI."
