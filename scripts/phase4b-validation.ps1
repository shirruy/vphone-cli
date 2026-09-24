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
Write-Host " VPHONE WINDOWS PORT - PHASE 4B ARCHIVE VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04b-archive-restore-parity") {
    throw "PHASE 4B FAIL: expected phase/04b-archive-restore-parity, found '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4B FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4b-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

Invoke-Checked -Label "[1/6] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/6] Phase 4B compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4b\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4B FAIL: census has unclassified compile units."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4B FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}

foreach ($category in @("PORTABLE", "SHIMMABLE", "REWRITE", "APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4B FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/6] Configure archive parity build" -Action {
    if (Test-Path ".\build\windows-phase4b") {
        Remove-Item ".\build\windows-phase4b" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4b"
}

Invoke-Checked -Label "[4/6] Build archive parity targets" -Action {
    cmake --build ".\build\windows-phase4b" --config Release
}

Invoke-Checked -Label "[5/6] Execute Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4b" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/6] Verify archive capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4b" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4B FAIL: vphone-cli-win.exe was not produced."
}

$json = & $cli.FullName archive-capabilities
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4B FAIL: archive-capabilities command failed."
}

$cap = ($json -join [Environment]::NewLine) | ConvertFrom-Json

if ($cap.gnutar_uncompressed -ne "supported") { throw "PHASE 4B FAIL: GNU tar capability drift." }
if ($cap.member_read -ne "supported") { throw "PHASE 4B FAIL: member_read capability drift." }

foreach ($name in @("zstd", "xz", "gzip", "darwin_xattrs_acl")) {
    if ($cap.$name -ne "unsupported") {
        throw "PHASE 4B FAIL: $name must remain unsupported until a real parity proof exists."
    }
}

$tests = ctest --test-dir ".\build\windows-phase4b" -C Release -N
if (($tests -join [Environment]::NewLine) -notmatch "archive_gnutar_roundtrip") {
    throw "PHASE 4B FAIL: archive_gnutar_roundtrip is not registered."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4B ARCHIVE PARITY PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units      : $($census.compile_units)"
Write-Host "Unknown            : $($census.unknown_count)"
Write-Host "GNU tar            : $($cap.gnutar_uncompressed)"
Write-Host "Archive member read: $($cap.member_read)"
Write-Host "Compression        : explicitly unsupported"
Write-Host "Darwin metadata    : explicitly unsupported"
Write-Host ""
Write-Host "Phase 4 remains open. Broader restore parity and Apple-specific image/seal replacements remain."
