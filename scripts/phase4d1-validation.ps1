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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D1 RESTORE IMAGE PARITY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d-restore-image-backend") {
    throw "PHASE 4D1 FAIL: expected phase/04d-restore-image-backend, found '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4D1 FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d1-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/6] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/6] Phase 4D1 compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d1\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4D1 FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D1 FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE", "SHIMMABLE", "REWRITE", "APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D1 FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/6] Configure restore image parity build" -Action {
    if (Test-Path ".\build\windows-phase4d1") {
        Remove-Item ".\build\windows-phase4d1" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4d1"
}

Invoke-Checked -Label "[4/6] Build restore image parity targets" -Action {
    cmake --build ".\build\windows-phase4d1" --config Release
}

Invoke-Checked -Label "[5/6] Execute Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d1" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/6] Verify restore/image capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4d1" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4D1 FAIL: vphone-cli-win.exe was not produced."
}

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D1 FAIL: restore-capabilities command failed."
}

if ($cap.apfs_snapshot_rename -ne "supported") {
    throw "PHASE 4D1 FAIL: APFS snapshot rename is not supported."
}

foreach ($name in @(
    "aea_decrypt_encrypt",
    "disk_image_attach_convert",
    "apfs_seal",
    "canonical_metadata_archive"
)) {
    if ($cap.$name -ne "unsupported") {
        throw "PHASE 4D1 FAIL: $name must remain unsupported until executable evidence exists."
    }
}

$tests = ctest --test-dir ".\build\windows-phase4d1" -C Release -N
$testText = $tests -join [Environment]::NewLine

foreach ($required in @(
    "apfs_snapshot_rename",
    "native_cli_restore_capabilities",
    "compression_transport_roundtrip",
    "bundle_manifest_validation"
)) {
    if ($testText -notmatch $required) {
        throw "PHASE 4D1 FAIL: required test '$required' is not registered."
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D1 RESTORE IMAGE PARITY PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units        : $($census.compile_units)"
Write-Host "Unknown              : $($census.unknown_count)"
Write-Host "APFS snapshot rename : $($cap.apfs_snapshot_rename)"
Write-Host "AEA                  : $($cap.aea_decrypt_encrypt)"
Write-Host "Disk image backend   : $($cap.disk_image_attach_convert)"
Write-Host "APFS seal            : $($cap.apfs_seal)"
Write-Host "Metadata archive     : $($cap.canonical_metadata_archive)"
Write-Host ""
Write-Host "Phase 4D remains open after this slice."
