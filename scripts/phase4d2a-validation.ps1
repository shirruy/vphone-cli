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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D2A AEA PROFILE 1 CORE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d-restore-image-backend") {
    throw "PHASE 4D2A FAIL: wrong branch '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4D2A FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d2a-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/6] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/6] Phase 4D2A compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d2a\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4D2A FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D2A FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D2A FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/6] Configure AEA core build" -Action {
    if (Test-Path ".\build\windows-phase4d2a") {
        Remove-Item ".\build\windows-phase4d2a" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4d2a"
}

Invoke-Checked -Label "[4/6] Build AEA core targets" -Action {
    cmake --build ".\build\windows-phase4d2a" --config Release
}

Invoke-Checked -Label "[5/6] Execute Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d2a" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/6] Verify AEA capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4d2a" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4D2A FAIL: vphone-cli-win.exe not produced."
}

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D2A FAIL: restore-capabilities failed."
}

if ($cap.apfs_snapshot_rename -ne "supported") {
    throw "PHASE 4D2A FAIL: APFS snapshot regression."
}
if ($cap.aea_profile1_symmetric_core -ne "supported") {
    throw "PHASE 4D2A FAIL: AEA profile 1 core not supported."
}
if ($cap.aea_decrypt_encrypt -ne "unsupported") {
    throw "PHASE 4D2A FAIL: full AEA backend must remain unsupported until streaming/interoperability proof."
}

foreach ($name in @(
    "disk_image_attach_convert",
    "apfs_seal",
    "canonical_metadata_archive"
)) {
    if ($cap.$name -ne "unsupported") {
        throw "PHASE 4D2A FAIL: $name must remain unsupported."
    }
}

$tests = ctest --test-dir ".\build\windows-phase4d2a" -C Release -N
$testText = $tests -join [Environment]::NewLine

foreach ($required in @(
    "aea_profile1_symmetric_roundtrip",
    "apfs_snapshot_rename",
    "compression_transport_roundtrip",
    "bundle_manifest_validation"
)) {
    if ($testText -notmatch $required) {
        throw "PHASE 4D2A FAIL: required test '$required' is not registered."
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D2A AEA PROFILE 1 CORE PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units         : $($census.compile_units)"
Write-Host "Unknown               : $($census.unknown_count)"
Write-Host "AEA profile 1 core    : $($cap.aea_profile1_symmetric_core)"
Write-Host "Full AEA file backend : $($cap.aea_decrypt_encrypt)"
Write-Host "APFS snapshot rename  : $($cap.apfs_snapshot_rename)"
Write-Host ""
Write-Host "Phase 4D2 remains open for streaming and independent interoperability proof."
