$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][scriptblock]$Action
    )

    Write-Host ""
    Write-Host $Label -ForegroundColor Yellow

    & $Action

    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

# PowerShell provider location and .NET process current directory are not
# guaranteed to remain synchronized. System.IO APIs resolve relative paths
# against Environment.CurrentDirectory, so explicitly pin both to repo root.
[Environment]::CurrentDirectory = $repoRoot

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VPHONE WINDOWS PORT - PHASE 4D4B PROMOTION VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()

if ($branch -ne "phase/04d4b-fixed-vhd-attach-promote") {
    throw "PHASE 4D4B FAIL: wrong branch '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4D4B FAIL: working tree is not clean."
}

$head = (git rev-parse HEAD).Trim()

Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"


Invoke-Checked "[1/8] Windows preflight" {
    & "$PSScriptRoot\windows-preflight.ps1"
}


Write-Host ""
Write-Host "[2/8] Portability census..." -ForegroundColor Yellow

$evidenceDir = ".\build\phase4d4b-evidence"

if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

& "$PSScriptRoot\phase1-census.ps1" -OutputDirectory $evidenceDir

if ($LASTEXITCODE -ne 0) {
    throw "Phase 4D4B census failed."
}

$census = Get-Content `
    "$evidenceDir\census_results.runtime.json" `
    -Raw | ConvertFrom-Json

$baseline = Get-Content `
    ".\artifacts\evidence\phase4d4a\census_results.json" `
    -Raw | ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4D4B FAIL: unknown compile units remain."
}

if ($census.compile_units -ne $baseline.compile_units) {
    throw "PHASE 4D4B FAIL: compile-unit drift."
}

foreach ($category in @(
    "PORTABLE",
    "SHIMMABLE",
    "REWRITE",
    "APPLE_ONLY"
)) {
    if ($census.categories.$category -ne $baseline.categories.$category) {
        throw "PHASE 4D4B FAIL: census drift in $category."
    }
}

Write-Host "PORTABILITY CENSUS PASS" -ForegroundColor Green


$buildDir = ".\build\windows-phase4d4b"

Write-Host ""
Write-Host "[3/8] Clean configure..." -ForegroundColor Yellow

if (Test-Path $buildDir) {
    Remove-Item $buildDir -Recurse -Force
}

cmake `
    -S ".\windows" `
    -B $buildDir

if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D4B configure failed."
}


Invoke-Checked "[4/8] Release build" {
    cmake --build $buildDir --config Release
}


Invoke-Checked "[5/8] Complete Release test suite" {
    ctest `
        --test-dir $buildDir `
        -C Release `
        --output-on-failure
}


Write-Host ""
Write-Host "[6/8] Verifying promoted capability boundary..." -ForegroundColor Yellow

$cli = Get-ChildItem `
    $buildDir `
    -Filter "vphone-cli-win.exe" `
    -File `
    -Recurse |
    Select-Object -First 1

if (-not $cli) {
    throw "vphone-cli-win.exe missing."
}

$firmware = (
    (& $cli.FullName firmware-capabilities) `
    -join [Environment]::NewLine
) | ConvertFrom-Json

$restore = (
    (& $cli.FullName restore-capabilities) `
    -join [Environment]::NewLine
) | ConvertFrom-Json

foreach ($cap in @($firmware, $restore)) {

    if ($cap.disk_image_fixed_vhd_convert -ne "supported") {
        throw "Fixed VHD conversion regressed."
    }

    if ($cap.disk_image_fixed_vhd_attach_readonly -ne "supported") {
        throw "Read-only attach was not promoted."
    }

    if ($cap.disk_image_attach_convert -ne "unsupported") {
        throw "Aggregate attach/convert promoted prematurely."
    }

    if ($cap.apfs_seal -ne "unsupported") {
        throw "APFS seal promoted prematurely."
    }

    if ($cap.canonical_metadata_archive -ne "unsupported") {
        throw "Metadata archive promoted prematurely."
    }
}

Write-Host "Capability promotion boundary PASS" -ForegroundColor Green


Write-Host ""
Write-Host "[7/8] Creating physical fixed VHD smoke image..." -ForegroundColor Yellow

$diskTool = Get-ChildItem `
    $buildDir `
    -Filter "vphone-disk-image-win.exe" `
    -File `
    -Recurse |
    Select-Object -First 1

if (-not $diskTool) {
    throw "vphone-disk-image-win.exe missing."
}

$probeDir = Join-Path $repoRoot "build\phase4d4b-physical"

if (Test-Path $probeDir) {
    Remove-Item $probeDir -Recurse -Force
}

New-Item `
    -ItemType Directory `
    -Path $probeDir `
    -Force | Out-Null

$rawPath = Join-Path $probeDir "promotion-probe.raw"
$vhdPath = Join-Path $probeDir "promotion-probe.vhd"

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

$convert = & $diskTool.FullName `
    convert-fixed `
    $rawPath `
    $vhdPath

if ($LASTEXITCODE -ne 0) {
    throw "Fixed VHD conversion smoke failed."
}

$convert | Write-Host

if (-not (Test-Path $vhdPath)) {
    throw "Fixed VHD output missing."
}

if ((Get-Item $vhdPath).Length -ne ($size + 512)) {
    throw "Fixed VHD size mismatch."
}


Write-Host ""
Write-Host "[8/8] Physical Windows read-only attach..." -ForegroundColor Yellow

$probeOutput = & $diskTool.FullName `
    probe-attach-readonly `
    $vhdPath

if ($LASTEXITCODE -ne 0) {
    throw "Physical VHD read-only attach failed."
}

$probeText = $probeOutput -join [Environment]::NewLine
$probe = $probeText | ConvertFrom-Json

if (-not $probe.physical_path) {
    throw "Windows returned no physical disk path."
}

if ($probe.detached -ne $true) {
    throw "Virtual disk was not confirmed detached."
}

$probeOutput | Write-Host

Write-Host ""
Write-Host "PHYSICAL_ATTACH_PROBE=PASS" -ForegroundColor Green
Write-Host "PHYSICAL_PATH=$($probe.physical_path)" -ForegroundColor Green


Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D4B PHYSICAL WINDOWS VERIFIED PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Commit                     : $head" -ForegroundColor Green
Write-Host "Fixed VHD conversion       : supported" -ForegroundColor Green
Write-Host "Read-only VHD attach       : supported" -ForegroundColor Green
Write-Host "Aggregate attach/convert   : unsupported" -ForegroundColor Yellow
Write-Host "Physical attach            : PASS" -ForegroundColor Green
Write-Host "Automatic detach           : PASS" -ForegroundColor Green
