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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D4 BASELINE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d4-disk-image-attach-convert") {
    throw "PHASE 4D4 BASELINE FAIL: wrong branch '$branch'"
}
if (git status --porcelain) {
    throw "PHASE 4D4 BASELINE FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d4-baseline-evidence"
if (Test-Path $evidenceDir) { Remove-Item $evidenceDir -Recurse -Force }

Invoke-Checked -Label "[1/6] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/6] Phase 4D4 compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d4\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) { throw "PHASE 4D4 BASELINE FAIL: census has unclassified compile units." }
if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D4 BASELINE FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}
foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D4 BASELINE FAIL: category drift for $category."
    }
}

Write-Host ""
Write-Host "[3/6] Verifying inherited Phase 4D3E implementation..." -ForegroundColor Yellow

$requiredFiles = @(
    ".\windows\src\udif_portable.cpp",
    ".\windows\src\cli_main.cpp",
    ".\scripts\phase4d3e_udif_adc_oracle.py",
    ".\docs\PHASE4D3E_UDIF_ADC_DECODE.md"
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        throw "Missing inherited artifact: $file"
    }
    Write-Host "FOUND: $file" -ForegroundColor Green
}

Invoke-Checked -Label "[4/6] Configure and build inherited native Windows baseline" -Action {
    if (Test-Path ".\build\windows-phase4d4-baseline") {
        Remove-Item ".\build\windows-phase4d4-baseline" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4d4-baseline"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cmake --build ".\build\windows-phase4d4-baseline" --config Release
}

Invoke-Checked -Label "[5/6] Execute inherited Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d4-baseline" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/6] Verify exact capability boundary" -ForegroundColor Yellow

$cli = Get-ChildItem ".\build\windows-phase4d4-baseline" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) { throw "PHASE 4D4 BASELINE FAIL: vphone-cli-win.exe was not produced." }

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D4 BASELINE FAIL: restore-capabilities failed." }

foreach ($name in @(
    "disk_image_udrw_raw_convert",
    "disk_image_udif_zlib_decode",
    "disk_image_udif_lzfse_decode",
    "disk_image_udif_bzip2_decode",
    "disk_image_udif_adc_decode"
)) {
    if ($cap.$name -ne "supported") {
        throw "PHASE 4D4 BASELINE FAIL: inherited capability regressed: $name=$($cap.$name)"
    }
}

if ($cap.disk_image_attach_convert -ne "unsupported") {
    throw "PHASE 4D4 BASELINE FAIL: attach/convert is not a clean unsupported baseline."
}
if ($cap.apfs_seal -ne "unsupported") {
    throw "PHASE 4D4 BASELINE FAIL: APFS seal promoted prematurely."
}
if ($cap.canonical_metadata_archive -ne "unsupported") {
    throw "PHASE 4D4 BASELINE FAIL: canonical metadata archive promoted prematurely."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D4 BASELINE VERIFIED PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Commit                    : $head"
Write-Host "Compile units             : $($census.compile_units)"
Write-Host "Unknown                   : $($census.unknown_count)"
Write-Host "RAW                       : supported"
Write-Host "ZLIB                      : supported"
Write-Host "LZFSE                     : supported"
Write-Host "BZIP2                     : supported"
Write-Host "ADC                       : supported"
Write-Host "Disk image attach/convert : unsupported TARGET"
Write-Host "APFS seal                 : unsupported"
Write-Host "Metadata archive          : unsupported"
