$ErrorActionPreference = "Stop"

param(
    [switch]$AllowDetachedHead
)

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
Write-Host " VPHONE WINDOWS PORT - PHASE 1 VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to resolve current Git branch."
}

if (-not $AllowDetachedHead -and $branch -ne "phase/01-portability-census") {
    throw "PHASE 1 FAIL: expected branch phase/01-portability-census, found '$branch'"
}

$dirty = git status --porcelain
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read Git status."
}
if ($dirty) {
    throw "PHASE 1 FAIL: working tree is not clean before validation."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase1-evidence"
if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}
New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

Invoke-Checked -Label "[1/5] Full compile-unit portability census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$runtimeResults = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baselineResults = Get-Content "artifacts/evidence/phase1/census_results.json" -Raw | ConvertFrom-Json

if ($runtimeResults.unknown_count -ne 0) {
    throw "PHASE 1 FAIL: runtime census has unclassified compile units."
}

if ($runtimeResults.compile_units -ne $baselineResults.compile_units) {
    throw "PHASE 1 FAIL: compile-unit count drift. Runtime=$($runtimeResults.compile_units), baseline=$($baselineResults.compile_units)"
}

foreach ($category in @("PORTABLE", "SHIMMABLE", "REWRITE", "APPLE_ONLY")) {
    $runtimeCount = $runtimeResults.categories.$category
    $baselineCount = $baselineResults.categories.$category
    if ($runtimeCount -ne $baselineCount) {
        throw "PHASE 1 FAIL: category drift for $category. Runtime=$runtimeCount, baseline=$baselineCount"
    }
}

Invoke-Checked -Label "[2/5] Configure Windows build including upstream FTAB proof" -Action {
    if (Test-Path ".\build\windows-phase1") {
        Remove-Item ".\build\windows-phase1" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase1"
}

Invoke-Checked -Label "[3/5] Build Windows targets" -Action {
    cmake --build ".\build\windows-phase1" --config Release
}

Invoke-Checked -Label "[4/5] Execute complete CTest suite" -Action {
    ctest --test-dir ".\build\windows-phase1" -C Release --output-on-failure
}

Write-Host ""
Write-Host "[5/5] Verify upstream-derived FTAB proof executed" -ForegroundColor Yellow
$testList = ctest --test-dir ".\build\windows-phase1" -C Release -N
if ($LASTEXITCODE -ne 0) {
    throw "Unable to enumerate CTest suite."
}
if (($testList -join "`n") -notmatch "upstream_ftab_roundtrip") {
    throw "PHASE 1 FAIL: upstream_ftab_roundtrip test is not registered."
}

$ftabExe = Get-ChildItem ".\build\windows-phase1" -Filter "vphone_upstream_ftab_test.exe" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ftabExe) {
    throw "PHASE 1 FAIL: upstream-derived FTAB test executable was not built."
}

$environment = [ordered]@{
    branch = $branch
    head = $head
    os = (Get-CimInstance Win32_OperatingSystem).Caption
    os_version = (Get-CimInstance Win32_OperatingSystem).Version
    architecture = $env:PROCESSOR_ARCHITECTURE
    cmake = ((cmake --version | Select-Object -First 1) -join "")
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
}
$environment | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $evidenceDir "environment.json") -Encoding utf8

$results = [ordered]@{
    status = "PASS"
    compile_units = $runtimeResults.compile_units
    categories = $runtimeResults.categories
    unknown_count = $runtimeResults.unknown_count
    upstream_module = "MobileRestoreCore/Firmware/Containers/ftab.c"
    upstream_test = "upstream_ftab_roundtrip"
    upstream_test_executable = $ftabExe.FullName
}
$results | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $evidenceDir "results.json") -Encoding utf8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 1 VALIDATION PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Compile units classified : $($runtimeResults.compile_units)"
Write-Host "Unknown                  : $($runtimeResults.unknown_count)"
Write-Host "Upstream Windows proof   : upstream_ftab_roundtrip"
Write-Host "Evidence directory       : $evidenceDir"
Write-Host ""
Write-Host "This proves census completeness and one upstream-derived Windows compile/test."
Write-Host "It does NOT prove the full CLI/core, firmware pipeline, or VM boot."
