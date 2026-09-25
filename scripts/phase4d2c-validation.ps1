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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D2C BOUNDED STREAMING" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d-restore-image-backend") {
    throw "PHASE 4D2C FAIL: wrong branch '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4D2C FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d2c-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/8] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/8] Phase 4D2C compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d2c\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4D2C FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D2C FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D2C FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/8] Configure bounded streaming build" -Action {
    if (Test-Path ".\build\windows-phase4d2c") {
        Remove-Item ".\build\windows-phase4d2c" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4d2c"
}

Invoke-Checked -Label "[4/8] Build bounded streaming targets" -Action {
    cmake --build ".\build\windows-phase4d2c" --config Release
}

Invoke-Checked -Label "[5/8] Execute Release-mode suite including 80MB stress" -Action {
    ctest --test-dir ".\build\windows-phase4d2c" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/8] Independent AEA interoperability regression" -ForegroundColor Yellow

$venvPath = Join-Path (Get-Location) "build\phase4d2c-reference-venv"
& "$PSScriptRoot\setup-aea-reference.ps1" -VenvPath $venvPath
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D2C FAIL: reference environment setup failed."
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
$aeaTool = Get-ChildItem ".\build\windows-phase4d2c" -Filter "vphone-aea-win.exe" -File -Recurse | Select-Object -First 1
if (-not $aeaTool) {
    throw "PHASE 4D2C FAIL: vphone-aea-win.exe was not produced."
}

$interopDir = Join-Path (Get-Location) "build\phase4d2c-interop"
if (Test-Path $interopDir) {
    Remove-Item $interopDir -Recurse -Force
}

& $venvPython ".\scripts\phase4d2b_interop.py" --tool $aeaTool.FullName --workdir $interopDir
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D2C FAIL: independent bidirectional AEA interoperability failed."
}

Write-Host ""
Write-Host "[7/8] Verify bounded streaming telemetry contract" -ForegroundColor Yellow

$streamTest = Get-ChildItem ".\build\windows-phase4d2c" -Filter "vphone_aea_streaming_large_test.exe" -File -Recurse | Select-Object -First 1
if (-not $streamTest) {
    throw "PHASE 4D2C FAIL: streaming stress executable missing."
}

& $streamTest.FullName (Resolve-Path ".\build\windows-phase4d2c").Path
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D2C FAIL: direct streaming stress execution failed."
}

Write-Host ""
Write-Host "[8/8] Verify capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4d2c" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4D2C FAIL: vphone-cli-win.exe not produced."
}

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D2C FAIL: restore-capabilities failed."
}

if ($cap.apfs_snapshot_rename -ne "supported") {
    throw "PHASE 4D2C FAIL: APFS snapshot regression."
}
if ($cap.aea_profile1_symmetric_core -ne "supported") {
    throw "PHASE 4D2C FAIL: AEA core regression."
}
if ($cap.aea_profile1_file_backend -ne "supported") {
    throw "PHASE 4D2C FAIL: AEA file backend regression."
}
if ($cap.aea_independent_interop -ne "supported") {
    throw "PHASE 4D2C FAIL: independent interop regression."
}
if ($cap.aea_profile1_bounded_streaming -ne "supported") {
    throw "PHASE 4D2C FAIL: bounded streaming capability missing."
}
if ($cap.aea_decrypt_encrypt -ne "supported") {
    throw "PHASE 4D2C FAIL: full AEA capability was not promoted after dual-gate closure."
}

foreach ($name in @(
    "disk_image_attach_convert",
    "apfs_seal",
    "canonical_metadata_archive"
)) {
    if ($cap.$name -ne "unsupported") {
        throw "PHASE 4D2C FAIL: $name must remain unsupported."
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D2C BOUNDED STREAMING PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units             : $($census.compile_units)"
Write-Host "Unknown                   : $($census.unknown_count)"
Write-Host "AEA core                  : $($cap.aea_profile1_symmetric_core)"
Write-Host "AEA file backend          : $($cap.aea_profile1_file_backend)"
Write-Host "Independent interop       : $($cap.aea_independent_interop)"
Write-Host "Bounded streaming         : $($cap.aea_profile1_bounded_streaming)"
Write-Host "Full AEA capability       : $($cap.aea_decrypt_encrypt)"
Write-Host ""
Write-Host "Full AEA capability is promoted. This exact promotion commit must pass on physical Windows and CI."
