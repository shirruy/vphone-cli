param(
    [switch]$PhysicalAttachProbe
)

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
Write-Host " VPHONE WINDOWS PORT - PHASE 4D4A FIXED VHD" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($branch -ne "phase/04d4a-fixed-vhd-attach-convert") {
    throw "PHASE 4D4A FAIL: wrong branch '$branch'"
}
if (git status --porcelain) {
    throw "PHASE 4D4A FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

$evidenceDir = Join-Path (Get-Location) "build\phase4d4a-evidence"
if (Test-Path $evidenceDir) { Remove-Item $evidenceDir -Recurse -Force }

Invoke-Checked -Label "[1/8] Windows preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/8] Phase 4D4A compile-unit census" -Action {
    & "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir
}

$census = Get-Content (Join-Path $evidenceDir "census_results.runtime.json") -Raw | ConvertFrom-Json
$baseline = Get-Content ".\artifacts\evidence\phase4d4a\census_results.json" -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4D4A FAIL: census has unclassified compile units."
}
if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D4A FAIL: compile-unit drift. runtime=$($census.compile_units), baseline=$($baseline.compile_units)"
}
foreach ($category in @("PORTABLE","SHIMMABLE","REWRITE","APPLE_ONLY")) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D4A FAIL: category drift for $category."
    }
}

Invoke-Checked -Label "[3/8] Configure native Windows fixed VHD build" -Action {
    if (Test-Path ".\build\windows-phase4d4a") {
        Remove-Item ".\build\windows-phase4d4a" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows-phase4d4a"
}

Invoke-Checked -Label "[4/8] Build native Windows fixed VHD targets" -Action {
    cmake --build ".\build\windows-phase4d4a" --config Release
}

Invoke-Checked -Label "[5/8] Execute complete Release-mode suite" -Action {
    ctest --test-dir ".\build\windows-phase4d4a" -C Release --output-on-failure
}

$diskTool = Get-ChildItem ".\build\windows-phase4d4a" -Filter "vphone-disk-image-win.exe" -File -Recurse | Select-Object -First 1
if (-not $diskTool) {
    throw "PHASE 4D4A FAIL: vphone-disk-image-win.exe was not produced."
}

$cli = Get-ChildItem ".\build\windows-phase4d4a" -Filter "vphone-cli-win.exe" -File -Recurse | Select-Object -First 1
if (-not $cli) {
    throw "PHASE 4D4A FAIL: vphone-cli-win.exe was not produced."
}

Write-Host ""
Write-Host "[6/8] Verify granular capability boundary" -ForegroundColor Yellow

$capJson = (& $cli.FullName restore-capabilities) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D4A FAIL: restore-capabilities failed."
}
$cap = $capJson | ConvertFrom-Json

foreach ($name in @(
    "disk_image_udrw_raw_convert",
    "disk_image_udif_zlib_decode",
    "disk_image_udif_lzfse_decode",
    "disk_image_udif_bzip2_decode",
    "disk_image_udif_adc_decode",
    "disk_image_fixed_vhd_convert"
)) {
    if ($cap.$name -ne "supported") {
        throw "PHASE 4D4A FAIL: capability regressed or missing: $name=$($cap.$name)"
    }
}

if ($cap.disk_image_fixed_vhd_attach_readonly -ne "implemented_not_promoted") {
    throw "PHASE 4D4A FAIL: attach probe capability boundary is unexpected."
}
if ($cap.disk_image_attach_convert -ne "unsupported") {
    throw "PHASE 4D4A FAIL: aggregate attach/convert promoted before physical gate."
}
if ($cap.apfs_seal -ne "unsupported") {
    throw "PHASE 4D4A FAIL: APFS sealing promoted prematurely."
}
if ($cap.canonical_metadata_archive -ne "unsupported") {
    throw "PHASE 4D4A FAIL: metadata archive promoted prematurely."
}

Write-Host ""
Write-Host "[7/8] Native fixed VHD conversion smoke" -ForegroundColor Yellow

$probeDir = Join-Path (Get-Location) "build\phase4d4a-physical-probe"
if (Test-Path $probeDir) { Remove-Item $probeDir -Recurse -Force }
New-Item -ItemType Directory -Path $probeDir -Force | Out-Null

$rawPath = Join-Path $probeDir "probe.raw"
$vhdPath = Join-Path $probeDir "probe.vhd"

$size = 8MB
$stream = [System.IO.File]::Open(
    $rawPath,
    [System.IO.FileMode]::Create,
    [System.IO.FileAccess]::ReadWrite,
    [System.IO.FileShare]::None
)
try {
    $stream.SetLength($size)
    $stream.Position = 510
    $stream.WriteByte(0x55)
    $stream.WriteByte(0xAA)
    $stream.Flush()
}
finally {
    $stream.Dispose()
}

$convertOutput = & $diskTool.FullName convert-fixed $rawPath $vhdPath
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D4A FAIL: convert-fixed smoke failed."
}
$convertOutput | Write-Host

if (-not (Test-Path $vhdPath)) {
    throw "PHASE 4D4A FAIL: fixed VHD was not created."
}
if ((Get-Item $vhdPath).Length -ne ($size + 512)) {
    throw "PHASE 4D4A FAIL: fixed VHD output size mismatch."
}

Write-Host ""
Write-Host "[8/8] Physical Windows read-only attach probe" -ForegroundColor Yellow

if ($PhysicalAttachProbe) {
    $probeOutput = & $diskTool.FullName probe-attach-readonly $vhdPath
    if ($LASTEXITCODE -ne 0) {
        throw "PHASE 4D4A FAIL: Windows Virtual Disk attach probe failed."
    }

    $probeText = $probeOutput -join [Environment]::NewLine
    $probe = $probeText | ConvertFrom-Json

    if (-not $probe.physical_path) {
        throw "PHASE 4D4A FAIL: Windows returned an empty physical disk path."
    }
    if ($probe.detached -ne $true) {
        throw "PHASE 4D4A FAIL: attach probe did not confirm detach."
    }

    $probeOutput | Write-Host
    Write-Host "PHYSICAL_ATTACH_PROBE=PASS" -ForegroundColor Green
    Write-Host "PHYSICAL_PATH=$($probe.physical_path)" -ForegroundColor Green
}
else {
    Write-Host "PHYSICAL_ATTACH_PROBE=NOT_RUN" -ForegroundColor Yellow
    Write-Host "Run again with -PhysicalAttachProbe on elevated physical Windows." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D4A VALIDATION PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Commit                    : $head"
Write-Host "Compile units             : $($census.compile_units)"
Write-Host "Unknown                   : $($census.unknown_count)"
Write-Host "Fixed VHD convert         : supported"
Write-Host "Read-only attach probe    : $(if ($PhysicalAttachProbe) { 'PHYSICAL PASS' } else { 'IMPLEMENTED / NOT PROMOTED' })"
Write-Host "Aggregate attach/convert  : unsupported pending promotion"
Write-Host "APFS seal                 : unsupported"
Write-Host "Metadata archive          : unsupported"
