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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D3D BZIP2 UDIF DECODE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d3d-udif-bzip2-decode") {
    throw "PHASE 4D3D FAIL: wrong branch '$branch'"
}
if (git status --porcelain) {
    throw "PHASE 4D3D FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d3d-evidence"
if (Test-Path $evidenceDir) { Remove-Item $evidenceDir -Recurse -Force }

Invoke-Checked -Label "[1/10] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/10] Phase 4D3D compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d3d\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) { throw "PHASE 4D3D FAIL: census has unclassified compile units." }
if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D3D FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}
foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D3D FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/10] Configure native Windows UDIF/BZIP2 build" -Action {
    if (Test-Path ".\build\windows-phase4d3d") { Remove-Item ".\build\windows-phase4d3d" -Recurse -Force }
    cmake -S ".\windows" -B ".\build\windows-phase4d3d"
}

Invoke-Checked -Label "[4/10] Build UDIF/BZIP2 targets" -Action {
    cmake --build ".\build\windows-phase4d3d" --config Release
}

Invoke-Checked -Label "[5/10] Execute complete Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d3d" -C Release --output-on-failure
}

$tool = Get-ChildItem ".\build\windows-phase4d3d" -Filter "vphone-udif-win.exe" -File -Recurse | Select-Object -First 1
if (-not $tool) { throw "PHASE 4D3D FAIL: vphone-udif-win.exe was not produced." }

Write-Host ""
Write-Host "[6/10] Phase 4D3A RAW/UDRW regression oracle" -ForegroundColor Yellow
$rawDir = Join-Path (Get-Location) "build\phase4d3d-raw-regression"
if (Test-Path $rawDir) { Remove-Item $rawDir -Recurse -Force }
python ".\scripts\phase4d3a_udif_oracle.py" --tool $tool.FullName --workdir $rawDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3D FAIL: Phase 4D3A oracle failed." }

Write-Host ""
Write-Host "[7/10] Phase 4D3B zlib regression oracle" -ForegroundColor Yellow
$zlibDir = Join-Path (Get-Location) "build\phase4d3d-zlib-regression"
if (Test-Path $zlibDir) { Remove-Item $zlibDir -Recurse -Force }
python ".\scripts\phase4d3b_udif_zlib_oracle.py" --tool $tool.FullName --workdir $zlibDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3D FAIL: Phase 4D3B oracle failed." }

Write-Host ""
Write-Host "[8/10] Phase 4D3C LZFSE regression oracle" -ForegroundColor Yellow
python -m pip install --disable-pip-version-check --no-input "pyliblzfse==0.4.1"
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3D FAIL: pyliblzfse install failed." }

$lzfseDir = Join-Path (Get-Location) "build\phase4d3d-lzfse-regression"
if (Test-Path $lzfseDir) { Remove-Item $lzfseDir -Recurse -Force }
python ".\scripts\phase4d3c_udif_lzfse_oracle.py" --tool $tool.FullName --workdir $lzfseDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3D FAIL: Phase 4D3C oracle failed." }

Write-Host ""
Write-Host "[9/10] Independent BZIP2 UDIF oracle" -ForegroundColor Yellow
$bzipDir = Join-Path (Get-Location) "build\phase4d3d-bzip2-oracle"
if (Test-Path $bzipDir) { Remove-Item $bzipDir -Recurse -Force }
python ".\scripts\phase4d3d_udif_bzip2_oracle.py" --tool $tool.FullName --workdir $bzipDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3D FAIL: BZIP2 UDIF oracle failed." }

Write-Host ""
Write-Host "[10/10] Verify capability boundary" -ForegroundColor Yellow
$cli = Get-ChildItem ".\build\windows-phase4d3d" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) { throw "PHASE 4D3D FAIL: vphone-cli-win.exe was not produced." }

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3D FAIL: restore-capabilities failed." }

if ($cap.disk_image_udrw_raw_convert -ne "supported") { throw "PHASE 4D3D FAIL: UDRW/raw regressed." }
if ($cap.disk_image_udif_zlib_decode -ne "supported") { throw "PHASE 4D3D FAIL: zlib regressed." }
if ($cap.disk_image_udif_lzfse_decode -ne "supported") { throw "PHASE 4D3D FAIL: LZFSE regressed." }
if ($cap.disk_image_udif_bzip2_decode -ne "supported") { throw "PHASE 4D3D FAIL: BZIP2 capability missing." }
if ($cap.disk_image_attach_convert -ne "unsupported") { throw "PHASE 4D3D FAIL: aggregate attach/convert promoted prematurely." }
if ($cap.apfs_seal -ne "unsupported") { throw "PHASE 4D3D FAIL: APFS sealing promoted prematurely." }
if ($cap.canonical_metadata_archive -ne "unsupported") { throw "PHASE 4D3D FAIL: canonical metadata archive promoted prematurely." }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D3D BZIP2 UDIF DECODE PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units              : $($census.compile_units)"
Write-Host "Unknown                    : $($census.unknown_count)"
Write-Host "UDRW/raw conversion        : $($cap.disk_image_udrw_raw_convert)"
Write-Host "UDIF zlib decode           : $($cap.disk_image_udif_zlib_decode)"
Write-Host "UDIF LZFSE decode          : $($cap.disk_image_udif_lzfse_decode)"
Write-Host "UDIF BZIP2 decode          : $($cap.disk_image_udif_bzip2_decode)"
Write-Host "Full disk attach/convert   : $($cap.disk_image_attach_convert)"
Write-Host "APFS seal                  : $($cap.apfs_seal)"
Write-Host "Canonical metadata archive : $($cap.canonical_metadata_archive)"
Write-Host ""
Write-Host "This slice proves fail-closed BZIP2 UDIF decode while preserving RAW, zlib, and LZFSE parity."
Write-Host "ADC, other unimplemented UDIF codecs, APFS/HFS mounting, filesystem-aware resize, and sealing remain unsupported."
