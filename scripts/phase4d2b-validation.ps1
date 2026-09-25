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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D2B AEA FILE + INTEROP" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d-restore-image-backend") {
    throw "PHASE 4D2B FAIL: wrong branch '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4D2B FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d2b-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/7] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/7] Phase 4D2B compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d2b\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4D2B FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D2B FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D2B FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/7] Configure AEA file backend" -Action {
    if (Test-Path ".\build\windows-phase4d2b") {
        Remove-Item ".\build\windows-phase4d2b" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4d2b"
}

Invoke-Checked -Label "[4/7] Build AEA file backend" -Action {
    cmake --build ".\build\windows-phase4d2b" --config Release
}

Invoke-Checked -Label "[5/7] Execute Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d2b" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/7] Independent AEA interoperability proof" -ForegroundColor Yellow

$venvPath = Join-Path (Get-Location) "build\phase4d2b-reference-venv"
& "$PSScriptRoot\setup-aea-reference.ps1" -VenvPath $venvPath
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D2B FAIL: reference environment setup failed."
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
$aeaTool = Get-ChildItem ".\build\windows-phase4d2b" -Filter "vphone-aea-win.exe" -File -Recurse | Select-Object -First 1
if (-not $aeaTool) {
    throw "PHASE 4D2B FAIL: vphone-aea-win.exe was not produced."
}

$interopDir = Join-Path (Get-Location) "build\phase4d2b-interop"
if (Test-Path $interopDir) {
    Remove-Item $interopDir -Recurse -Force
}

& $venvPython ".\scripts\phase4d2b_interop.py" --tool $aeaTool.FullName --workdir $interopDir
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D2B FAIL: independent bidirectional AEA interoperability failed."
}

Write-Host ""
Write-Host "[7/7] Verify AEA capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4d2b" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4D2B FAIL: vphone-cli-win.exe not produced."
}

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D2B FAIL: restore-capabilities failed."
}

if ($cap.apfs_snapshot_rename -ne "supported") {
    throw "PHASE 4D2B FAIL: APFS snapshot regression."
}
if ($cap.aea_profile1_symmetric_core -ne "supported") {
    throw "PHASE 4D2B FAIL: AEA core regression."
}
if ($cap.aea_profile1_file_backend -ne "supported") {
    throw "PHASE 4D2B FAIL: AEA file backend not supported."
}
if ($cap.aea_independent_interop -ne "supported") {
    throw "PHASE 4D2B FAIL: independent AEA interop not supported."
}
if ($cap.aea_decrypt_encrypt -ne "unsupported") {
    throw "PHASE 4D2B FAIL: full AEA backend must remain unsupported until bounded-memory streaming proof."
}

foreach ($name in @(
    "disk_image_attach_convert",
    "apfs_seal",
    "canonical_metadata_archive"
)) {
    if ($cap.$name -ne "unsupported") {
        throw "PHASE 4D2B FAIL: $name must remain unsupported."
    }
}

$tests = ctest --test-dir ".\build\windows-phase4d2b" -C Release -N
$testText = $tests -join [Environment]::NewLine

foreach ($required in @(
    "aea_profile1_symmetric_roundtrip",
    "aea_profile1_file_roundtrip",
    "apfs_snapshot_rename",
    "compression_transport_roundtrip"
)) {
    if ($testText -notmatch $required) {
        throw "PHASE 4D2B FAIL: required test '$required' is not registered."
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D2B AEA FILE + INTEROP PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units          : $($census.compile_units)"
Write-Host "Unknown                : $($census.unknown_count)"
Write-Host "AEA profile 1 core     : $($cap.aea_profile1_symmetric_core)"
Write-Host "AEA file backend       : $($cap.aea_profile1_file_backend)"
Write-Host "Independent interop    : $($cap.aea_independent_interop)"
Write-Host "Full AEA backend       : $($cap.aea_decrypt_encrypt)"
Write-Host ""
Write-Host "Phase 4D2C remains for bounded-memory streaming proof."
