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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D3C LZFSE UDIF DECODE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d3c-udif-lzfse-decode") {
    throw "PHASE 4D3C FAIL: wrong branch '$branch'"
}
if (git status --porcelain) {
    throw "PHASE 4D3C FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d3c-evidence"
if (Test-Path $evidenceDir) { Remove-Item $evidenceDir -Recurse -Force }

Invoke-Checked -Label "[1/9] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/9] Phase 4D3C compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d3c\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) { throw "PHASE 4D3C FAIL: census has unclassified compile units." }
if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D3C FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}
foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D3C FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/9] Configure native Windows UDIF/LZFSE build" -Action {
    if (Test-Path ".\build\windows-phase4d3c") { Remove-Item ".\build\windows-phase4d3c" -Recurse -Force }
    cmake -S ".\windows" -B ".\build\windows-phase4d3c"
}

Invoke-Checked -Label "[4/9] Build UDIF/LZFSE targets" -Action {
    cmake --build ".\build\windows-phase4d3c" --config Release
}

Invoke-Checked -Label "[5/9] Execute complete Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d3c" -C Release --output-on-failure
}

$tool = Get-ChildItem ".\build\windows-phase4d3c" -Filter "vphone-udif-win.exe" -File -Recurse | Select-Object -First 1
if (-not $tool) { throw "PHASE 4D3C FAIL: vphone-udif-win.exe was not produced." }

Write-Host ""
Write-Host "[6/9] Phase 4D3A RAW/UDRW regression oracle" -ForegroundColor Yellow
$rawDir = Join-Path (Get-Location) "build\phase4d3c-raw-regression"
if (Test-Path $rawDir) { Remove-Item $rawDir -Recurse -Force }
python ".\scripts\phase4d3a_udif_oracle.py" --tool $tool.FullName --workdir $rawDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3C FAIL: Phase 4D3A oracle failed." }

Write-Host ""
Write-Host "[7/9] Phase 4D3B zlib UDIF regression oracle" -ForegroundColor Yellow
$zlibDir = Join-Path (Get-Location) "build\phase4d3c-zlib-regression"
if (Test-Path $zlibDir) { Remove-Item $zlibDir -Recurse -Force }
python ".\scripts\phase4d3b_udif_zlib_oracle.py" --tool $tool.FullName --workdir $zlibDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3C FAIL: Phase 4D3B zlib oracle failed." }

Write-Host ""
Write-Host "[8/9] Independent LZFSE UDIF oracle" -ForegroundColor Yellow
python -m pip install --disable-pip-version-check --no-input "pyliblzfse==0.4.1"
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3C FAIL: pyliblzfse dependency install failed." }

$lzfseDir = Join-Path (Get-Location) "build\phase4d3c-lzfse-oracle"
if (Test-Path $lzfseDir) { Remove-Item $lzfseDir -Recurse -Force }
python ".\scripts\phase4d3c_udif_lzfse_oracle.py" --tool $tool.FullName --workdir $lzfseDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3C FAIL: independent LZFSE UDIF oracle failed." }

Write-Host ""
Write-Host "[9/9] Verify capability boundary" -ForegroundColor Yellow
$cli = Get-ChildItem ".\build\windows-phase4d3c" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) { throw "PHASE 4D3C FAIL: vphone-cli-win.exe was not produced." }

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3C FAIL: restore-capabilities failed." }

if ($cap.disk_image_udrw_raw_convert -ne "supported") { throw "PHASE 4D3C FAIL: UDRW/raw capability regressed." }
if ($cap.disk_image_udif_zlib_decode -ne "supported") { throw "PHASE 4D3C FAIL: zlib capability regressed." }
if ($cap.disk_image_udif_lzfse_decode -ne "supported") { throw "PHASE 4D3C FAIL: LZFSE UDIF capability missing." }
if ($cap.disk_image_attach_convert -ne "unsupported") { throw "PHASE 4D3C FAIL: aggregate attach/convert promoted prematurely." }
if ($cap.apfs_seal -ne "unsupported") { throw "PHASE 4D3C FAIL: APFS sealing promoted prematurely." }
if ($cap.canonical_metadata_archive -ne "unsupported") { throw "PHASE 4D3C FAIL: canonical metadata archive promoted prematurely." }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D3C LZFSE UDIF DECODE PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units              : $($census.compile_units)"
Write-Host "Unknown                    : $($census.unknown_count)"
Write-Host "UDRW/raw conversion        : $($cap.disk_image_udrw_raw_convert)"
Write-Host "UDIF zlib decode           : $($cap.disk_image_udif_zlib_decode)"
Write-Host "UDIF LZFSE decode          : $($cap.disk_image_udif_lzfse_decode)"
Write-Host "Full disk attach/convert   : $($cap.disk_image_attach_convert)"
Write-Host "APFS seal                  : $($cap.apfs_seal)"
Write-Host "Canonical metadata archive : $($cap.canonical_metadata_archive)"
Write-Host ""
Write-Host "This slice proves fail-closed whole-disk LZFSE UDIF decode while preserving RAW and zlib parity."
Write-Host "ADC, bzip2, xz/LZMA UDIF, APFS/HFS mounting, filesystem-aware resize, and sealing remain unsupported."
