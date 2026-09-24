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
Write-Host " VPHONE WINDOWS PORT - PHASE 4A VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04-firmware-restore-parity") {
    throw "PHASE 4A FAIL: expected phase/04-firmware-restore-parity, found '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4A FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4a-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/6] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/6] Phase 4A compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4A FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4A FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE", "SHIMMABLE", "REWRITE", "APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4A FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/6] Configure firmware parity build" -Action {
    if (Test-Path ".\build\windows-phase4") {
        Remove-Item ".\build\windows-phase4" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4"
}

Invoke-Checked -Label "[4/6] Build firmware parity targets" -Action {
    cmake --build ".\build\windows-phase4" --config Release
}

Invoke-Checked -Label "[5/6] Execute Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/6] Verify firmware capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4A FAIL: vphone-cli-win.exe was not produced."
}

$json = & $cli.FullName firmware-capabilities
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4A FAIL: firmware-capabilities command failed."
}

$cap = ($json -join [Environment]::NewLine) | ConvertFrom-Json

if ($cap.ftab -ne "supported") { throw "PHASE 4A FAIL: FTAB capability drift." }
if ($cap.mbn -ne "supported") { throw "PHASE 4A FAIL: MBN capability drift." }

foreach ($name in @(
    "aea_decrypt_encrypt",
    "disk_image_attach_convert",
    "apfs_seal",
    "canonical_metadata_archive"
)) {
    if ($cap.$name -ne "unsupported") {
        throw "PHASE 4A FAIL: $name must remain unsupported until a real Windows backend is proven."
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4A FIRMWARE PARITY PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units : $($census.compile_units)"
Write-Host "Unknown       : $($census.unknown_count)"
Write-Host "FTAB          : $($cap.ftab)"
Write-Host "MBN           : $($cap.mbn)"
Write-Host "AEA/APFS      : explicitly unsupported"
Write-Host ""
Write-Host "Phase 4 is NOT closed by this slice. Archive and broader restore parity remain."
