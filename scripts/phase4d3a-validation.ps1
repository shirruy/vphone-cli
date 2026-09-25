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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D3A UDRW CONTAINER PARITY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d3a-udrw-container") {
    throw "PHASE 4D3A FAIL: wrong branch '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4D3A FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d3a-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/7] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/7] Phase 4D3A compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d3a\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4D3A FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D3A FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D3A FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/7] Configure native Windows UDRW build" -Action {
    if (Test-Path ".\build\windows-phase4d3a") {
        Remove-Item ".\build\windows-phase4d3a" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4d3a"
}

Invoke-Checked -Label "[4/7] Build UDRW targets" -Action {
    cmake --build ".\build\windows-phase4d3a" --config Release
}

Invoke-Checked -Label "[5/7] Execute complete Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d3a" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/7] Independent Python UDIF oracle" -ForegroundColor Yellow

$tool = Get-ChildItem ".\build\windows-phase4d3a" -Filter "vphone-udif-win.exe" -File -Recurse | Select-Object -First 1
if (-not $tool) {
    throw "PHASE 4D3A FAIL: vphone-udif-win.exe was not produced."
}

$oracleDir = Join-Path (Get-Location) "build\phase4d3a-oracle"
if (Test-Path $oracleDir) {
    Remove-Item $oracleDir -Recurse -Force
}

python ".\scripts\phase4d3a_udif_oracle.py" --tool $tool.FullName --workdir $oracleDir
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D3A FAIL: independent UDIF oracle failed."
}

Write-Host ""
Write-Host "[7/7] Verify capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4d3a" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4D3A FAIL: vphone-cli-win.exe was not produced."
}

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D3A FAIL: restore-capabilities failed."
}

if ($cap.disk_image_udrw_raw_convert -ne "supported") {
    throw "PHASE 4D3A FAIL: UDRW/raw conversion capability missing."
}

if ($cap.disk_image_attach_convert -ne "unsupported") {
    throw "PHASE 4D3A FAIL: full attach/convert capability was promoted prematurely."
}

if ($cap.apfs_seal -ne "unsupported") {
    throw "PHASE 4D3A FAIL: APFS sealing was promoted prematurely."
}

if ($cap.canonical_metadata_archive -ne "unsupported") {
    throw "PHASE 4D3A FAIL: canonical metadata archive was promoted prematurely."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D3A UDRW CONTAINER PARITY PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units              : $($census.compile_units)"
Write-Host "Unknown                    : $($census.unknown_count)"
Write-Host "UDRW/raw conversion        : $($cap.disk_image_udrw_raw_convert)"
Write-Host "Full disk attach/convert   : $($cap.disk_image_attach_convert)"
Write-Host "APFS seal                  : $($cap.apfs_seal)"
Write-Host "Canonical metadata archive : $($cap.canonical_metadata_archive)"
Write-Host ""
Write-Host "This slice proves bounded-memory RAW <-> uncompressed UDIF/UDRW container parity only."
Write-Host "It does not claim APFS/HFS mounting, compressed DMG decoding, filesystem-aware resize, or sealing."
