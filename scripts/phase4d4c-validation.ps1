$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Label,

        [Parameter(Mandatory=$true)]
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host $Label -ForegroundColor Yellow

    & $Action

    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

$repoRoot = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

Set-Location $repoRoot
[Environment]::CurrentDirectory = $repoRoot

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VPHONE WINDOWS PORT - PHASE 4D4C" -ForegroundColor Cyan
Write-Host " AGGREGATE FIXED VHD ATTACH / CONVERT VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (
    git branch --show-current
).Trim()

if ($branch -ne "phase/04d4c-fixed-vhd-attach-convert-aggregate") {
    throw "PHASE 4D4C FAIL: wrong branch '$branch'"
}

if (git status --porcelain) {
    throw "PHASE 4D4C FAIL: working tree is not clean."
}

$head = (
    git rev-parse HEAD
).Trim()

Write-Host ""
Write-Host "Branch : $branch"
Write-Host "HEAD   : $head"

Invoke-Checked "[1/8] Windows preflight" {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Write-Host ""
Write-Host "[2/8] Portability census..." -ForegroundColor Yellow

$evidenceDir = ".\build\phase4d4c-evidence"

if (Test-Path $evidenceDir) {
    Remove-Item $evidenceDir -Recurse -Force
}

& "$PSScriptRoot\phase1-census.ps1" `
    -OutputDirectory $evidenceDir

if ($LASTEXITCODE -ne 0) {
    throw "Phase 4D4C census failed."
}

$census = Get-Content `
    "$evidenceDir\census_results.runtime.json" `
    -Raw |
    ConvertFrom-Json

if ($census.unknown_count -ne 0) {
    throw "PHASE 4D4C FAIL: unknown compile units remain."
}

Write-Host "Compile units : $($census.compile_units)"
Write-Host "Unknown       : $($census.unknown_count)"

Write-Host ""
Write-Host "PORTABILITY CENSUS PASS" -ForegroundColor Green

$buildDir = ".\build\windows-phase4d4c"

Write-Host ""
Write-Host "[3/8] Clean configure..." -ForegroundColor Yellow

if (Test-Path $buildDir) {
    Remove-Item $buildDir -Recurse -Force
}

cmake `
    -S ".\windows" `
    -B $buildDir

if ($LASTEXITCODE -ne 0) {
    throw "PHASE 4D4C configure failed."
}

Invoke-Checked "[4/8] Release build" {
    cmake `
        --build $buildDir `
        --config Release
}

Invoke-Checked "[5/8] Complete Release test suite" {
    ctest `
        --test-dir $buildDir `
        -C Release `
        --output-on-failure
}

Write-Host ""
Write-Host "[6/8] Verifying aggregate capability promotion..." -ForegroundColor Yellow

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

foreach ($cap in @(
    $firmware,
    $restore
)) {

    if ($cap.disk_image_fixed_vhd_convert -ne "supported") {
        throw "Fixed VHD conversion regressed."
    }

    if ($cap.disk_image_fixed_vhd_attach_readonly -ne "supported") {
        throw "Fixed VHD read-only attach regressed."
    }

    if ($cap.disk_image_attach_convert -ne "supported") {
        throw "Aggregate attach/convert was not promoted."
    }

    if ($cap.apfs_seal -ne "unsupported") {
        throw "APFS seal promoted prematurely."
    }

    if ($cap.canonical_metadata_archive -ne "unsupported") {
        throw "Metadata archive promoted prematurely."
    }
}

Write-Host "Aggregate capability promotion PASS" -ForegroundColor Green

Write-Host ""
Write-Host "[7/8] Creating physical aggregate smoke image..." -ForegroundColor Yellow

$diskTool = Get-ChildItem `
    $buildDir `
    -Filter "vphone-disk-image-win.exe" `
    -File `
    -Recurse |
    Select-Object -First 1

if (-not $diskTool) {
    throw "vphone-disk-image-win.exe missing."
}

$probeDir = Join-Path `
    $repoRoot `
    "build\phase4d4c-physical"

if (Test-Path $probeDir) {
    Remove-Item $probeDir -Recurse -Force
}

New-Item `
    -ItemType Directory `
    -Path $probeDir `
    -Force |
    Out-Null

$rawPath = Join-Path `
    $probeDir `
    "aggregate-probe.raw"

$vhdPath = Join-Path `
    $probeDir `
    "aggregate-probe.vhd"

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

$aggregateOutput = & $diskTool.FullName `
    convert-fixed-and-probe-readonly `
    $rawPath `
    $vhdPath

if ($LASTEXITCODE -ne 0) {
    throw "Aggregate physical operation failed."
}

$aggregateText = (
    $aggregateOutput `
    -join [Environment]::NewLine
)

$aggregate = $aggregateText |
    ConvertFrom-Json

if ($aggregate.operation -ne "convert-fixed-and-probe-readonly") {
    throw "Unexpected aggregate operation result."
}

if ($aggregate.raw_size -ne $size) {
    throw "Aggregate raw size mismatch."
}

if ($aggregate.vhd_size -ne ($size + 512)) {
    throw "Aggregate VHD size mismatch."
}

if (-not $aggregate.physical_path) {
    throw "Aggregate attach returned no physical path."
}

if ($aggregate.attached_readonly -ne $true) {
    throw "Aggregate operation did not confirm read-only attach."
}

if ($aggregate.detached -ne $true) {
    throw "Aggregate operation did not confirm detach."
}

if (-not (Test-Path $vhdPath)) {
    throw "Aggregate VHD output missing."
}

if ((Get-Item $vhdPath).Length -ne ($size + 512)) {
    throw "Aggregate physical VHD file size mismatch."
}

$aggregateOutput | Write-Host

$evidence = [ordered]@{
    phase                 = "4D4C"
    commit                = $head
    operation             = $aggregate.operation
    raw_size              = $aggregate.raw_size
    vhd_size              = $aggregate.vhd_size
    footer_checksum       = $aggregate.footer_checksum
    physical_path         = $aggregate.physical_path
    attached_readonly     = $aggregate.attached_readonly
    detached              = $aggregate.detached
    aggregate_capability  = "supported"
}

$evidence |
    ConvertTo-Json -Depth 5 |
    Set-Content `
        (Join-Path $probeDir "aggregate-evidence.json") `
        -Encoding UTF8

Write-Host ""
Write-Host "AGGREGATE_PHYSICAL_PROBE=PASS" -ForegroundColor Green
Write-Host "PHYSICAL_PATH=$($aggregate.physical_path)" -ForegroundColor Green

Write-Host ""
Write-Host "[8/8] Final capability boundary..." -ForegroundColor Yellow

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D4C PHYSICAL WINDOWS VERIFIED PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Commit                   : $head" -ForegroundColor Green
Write-Host "Fixed VHD conversion     : supported" -ForegroundColor Green
Write-Host "Read-only VHD attach     : supported" -ForegroundColor Green
Write-Host "Aggregate attach/convert : supported" -ForegroundColor Green
Write-Host "Physical attach          : PASS" -ForegroundColor Green
Write-Host "Automatic detach         : PASS" -ForegroundColor Green
Write-Host "APFS seal                : unsupported" -ForegroundColor Yellow
Write-Host "Metadata archive         : unsupported" -ForegroundColor Yellow