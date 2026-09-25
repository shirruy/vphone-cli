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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D3B ZLIB UDIF DECODE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d3b-udif-zlib-decode") {
    throw "PHASE 4D3B FAIL: wrong branch '$branch'"
}
if (git status --porcelain) {
    throw "PHASE 4D3B FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d3b-evidence"
if (Test-Path $evidenceDir) { Remove-Item $evidenceDir -Recurse -Force }

Invoke-Checked -Label "[1/8] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/8] Phase 4D3B compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d3b\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) { throw "PHASE 4D3B FAIL: census has unclassified compile units." }
if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D3B FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}
foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D3B FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/8] Configure native Windows UDIF build" -Action {
    if (Test-Path ".\build\windows-phase4d3b") { Remove-Item ".\build\windows-phase4d3b" -Recurse -Force }
    cmake -S ".\windows" -B ".\build\windows-phase4d3b"
}

Invoke-Checked -Label "[4/8] Build UDIF decode targets" -Action {
    cmake --build ".\build\windows-phase4d3b" --config Release
}

Invoke-Checked -Label "[5/8] Execute complete Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d3b" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[6/8] Re-run Phase 4D3A RAW/UDRW regression oracle" -ForegroundColor Yellow
$tool = Get-ChildItem ".\build\windows-phase4d3b" -Filter "vphone-udif-win.exe" -File -Recurse | Select-Object -First 1
if (-not $tool) { throw "PHASE 4D3B FAIL: vphone-udif-win.exe was not produced." }

$regressionDir = Join-Path (Get-Location) "build\phase4d3b-raw-regression"
if (Test-Path $regressionDir) { Remove-Item $regressionDir -Recurse -Force }
python ".\scripts\phase4d3a_udif_oracle.py" --tool $tool.FullName --workdir $regressionDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3B FAIL: Phase 4D3A RAW/UDRW regression oracle failed." }

Write-Host ""
Write-Host "[7/8] Independent compressed UDIF/zlib oracle" -ForegroundColor Yellow
$oracleDir = Join-Path (Get-Location) "build\phase4d3b-zlib-oracle"
if (Test-Path $oracleDir) { Remove-Item $oracleDir -Recurse -Force }
python ".\scripts\phase4d3b_udif_zlib_oracle.py" --tool $tool.FullName --workdir $oracleDir
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3B FAIL: compressed UDIF/zlib oracle failed." }

Write-Host ""
Write-Host "[8/8] Verify capability boundary" -ForegroundColor Yellow
$cli = Get-ChildItem ".\build\windows-phase4d3b" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) { throw "PHASE 4D3B FAIL: vphone-cli-win.exe was not produced." }

$cap = ((& $cli.FullName restore-capabilities) -join [Environment]::NewLine) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "PHASE 4D3B FAIL: restore-capabilities failed." }

if ($cap.disk_image_udrw_raw_convert -ne "supported") { throw "PHASE 4D3B FAIL: Phase 4D3A UDRW/raw capability regressed." }
if ($cap.disk_image_udif_zlib_decode -ne "supported") { throw "PHASE 4D3B FAIL: zlib UDIF decode capability missing." }
if ($cap.disk_image_attach_convert -ne "unsupported") { throw "PHASE 4D3B FAIL: aggregate disk attach/convert was promoted prematurely." }
if ($cap.apfs_seal -ne "unsupported") { throw "PHASE 4D3B FAIL: APFS sealing was promoted prematurely." }
if ($cap.canonical_metadata_archive -ne "unsupported") { throw "PHASE 4D3B FAIL: canonical metadata archive was promoted prematurely." }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D3B ZLIB UDIF DECODE PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units              : $($census.compile_units)"
Write-Host "Unknown                    : $($census.unknown_count)"
Write-Host "UDRW/raw conversion        : $($cap.disk_image_udrw_raw_convert)"
Write-Host "UDIF zlib decode           : $($cap.disk_image_udif_zlib_decode)"
Write-Host "Full disk attach/convert   : $($cap.disk_image_attach_convert)"
Write-Host "APFS seal                  : $($cap.apfs_seal)"
Write-Host "Canonical metadata archive : $($cap.canonical_metadata_archive)"
Write-Host ""
Write-Host "This slice proves fail-closed whole-disk UDIF decode for RAW, zero-fill, and zlib block runs."
Write-Host "ADC, bzip2, APFS/HFS mounting, filesystem-aware resize, and sealing remain unsupported."
