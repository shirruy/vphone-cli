$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

Set-Location $repoRoot
[Environment]::CurrentDirectory = $repoRoot

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VPHONE WINDOWS PORT - PHASE 5C VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$branch = (
    git branch --show-current
).Trim()

$commit = (
    git rev-parse HEAD
).Trim()

Write-Host "Branch : $branch" -ForegroundColor Cyan
Write-Host "HEAD   : $commit" -ForegroundColor Cyan

# ------------------------------------------------------------
# 1/9 Windows preflight
# ------------------------------------------------------------

Write-Host ""
Write-Host "[1/9] Windows preflight..." -ForegroundColor Yellow

& "$PSScriptRoot\windows-preflight.ps1"

if ($LASTEXITCODE -ne 0) {
    throw "Windows preflight failed."
}

# ------------------------------------------------------------
# 2/9 Upstream parity
# ------------------------------------------------------------

Write-Host ""
Write-Host "[2/9] Canonical upstream model parity..." -ForegroundColor Yellow

$upstream = Join-Path `
    $repoRoot `
    "VPhoneExecutable\VPhoneVirtualization\UI\VirtualMachine\VPhoneVirtualMachineHardwareModel.swift"

if (-not (Test-Path $upstream)) {
    throw "Upstream hardware model source missing."
}

$text = Get-Content $upstream -Raw

$tokens = @(
    "static let udidChipID: UInt32 = 0xFE01",
    "setPlatformVersion(NSNumber(value: UInt32(3)))",
    "setBoardID(NSNumber(value: UInt32(0x90)))",
    "setISA(NSNumber(value: Int64(2)))"
)

foreach ($token in $tokens) {

    if (
        $text -notmatch
        [regex]::Escape($token)
    ) {
        throw "Upstream parity failure: $token"
    }

    Write-Host "UPSTREAM : $token" -ForegroundColor Green
}

# ------------------------------------------------------------
# 3/9 QEMU provider inherited
# ------------------------------------------------------------

Write-Host ""
Write-Host "[3/9] Inherited Phase 5B ARM64 provider..." -ForegroundColor Yellow

$qemu = Get-Command `
    "qemu-system-aarch64.exe" `
    -ErrorAction SilentlyContinue

$qemuPath = $null

if ($qemu) {
    $qemuPath = $qemu.Source
}
else {
    $candidate = Join-Path `
        $env:ProgramFiles `
        "qemu\qemu-system-aarch64.exe"

    if (Test-Path $candidate) {
        $qemuPath = $candidate
    }
}

if (-not $qemuPath) {
    throw "Inherited QEMU ARM64 provider missing."
}

$qemuDir = Split-Path $qemuPath -Parent

if (
    ($env:Path -split ";") -notcontains
    $qemuDir
) {
    $env:Path = "$qemuDir;$env:Path"
}

$machines = (
    & $qemuPath -machine help
) -join [Environment]::NewLine

if ($LASTEXITCODE -ne 0) {
    throw "Unable to query QEMU machines."
}

if ($machines -notmatch "(?m)^\s*virt\s") {
    throw "Inherited QEMU virt machine missing."
}

Write-Host "QEMU ARM64 provider : PASS" -ForegroundColor Green

# ------------------------------------------------------------
# 4/9 Visual Studio generator
# ------------------------------------------------------------

Write-Host ""
Write-Host "[4/9] Selecting Visual Studio generator..." -ForegroundColor Yellow

$cmakeHelp = (
    & cmake --help 2>&1
) -join [Environment]::NewLine

$vswhereCandidates = @(
    (
        Join-Path `
            ${env:ProgramFiles(x86)} `
            "Microsoft Visual Studio\Installer\vswhere.exe"
    ),
    (
        Join-Path `
            $env:ProgramFiles `
            "Microsoft Visual Studio\Installer\vswhere.exe"
    )
)

$vswhere = $vswhereCandidates |
    Where-Object {
        $_ -and (Test-Path $_)
    } |
    Select-Object -First 1

if (-not $vswhere) {
    throw "vswhere.exe missing."
}

$vsJson = & $vswhere `
    -latest `
    -products '*' `
    -requires Microsoft.Component.MSBuild `
    -format json `
    -utf8

$instances = @(
    ($vsJson -join [Environment]::NewLine) |
    ConvertFrom-Json
)

$instance = $instances |
    Select-Object -First 1

if (-not $instance) {
    throw "Visual Studio installation unavailable."
}

$major = [int](
    $instance.installationVersion.Split('.')[0]
)

switch ($major) {

    { $_ -ge 18 } {
        $generator =
            "Visual Studio 18 2026"
        break
    }

    17 {
        $generator =
            "Visual Studio 17 2022"
        break
    }

    default {
        throw "Unsupported Visual Studio major $major."
    }
}

if (
    $cmakeHelp -notmatch
    [regex]::Escape($generator)
) {
    throw "CMake generator unavailable: $generator"
}

Write-Host "Generator : $generator" -ForegroundColor Green

# ------------------------------------------------------------
# 5/9 Clean Release build
# ------------------------------------------------------------

Write-Host ""
Write-Host "[5/9] Clean Release build..." -ForegroundColor Yellow

$buildDir = Join-Path `
    $repoRoot `
    "build\windows-phase05c"

if (Test-Path $buildDir) {
    Remove-Item `
        $buildDir `
        -Recurse `
        -Force
}

cmake `
    -S ".\windows" `
    -B $buildDir `
    -G $generator `
    -A x64

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5C CMake configuration failed."
}

cmake `
    --build $buildDir `
    --config Release `
    --parallel

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5C Release build failed."
}

# ------------------------------------------------------------
# 6/9 Complete Release tests
# ------------------------------------------------------------

Write-Host ""
Write-Host "[6/9] Complete Release test suite..." -ForegroundColor Yellow

ctest `
    --test-dir $buildDir `
    -C Release `
    --output-on-failure

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5C Release tests failed."
}

# ------------------------------------------------------------
# 7/9 Native machine model validation
# ------------------------------------------------------------

Write-Host ""
Write-Host "[7/9] Native Apple machine model validation..." -ForegroundColor Yellow

$modelExe = Get-ChildItem `
    $buildDir `
    -Recurse `
    -File `
    -Filter "vphone-apple-machine-win.exe" |
    Select-Object -First 1

if (-not $modelExe) {
    throw "vphone-apple-machine-win.exe not produced."
}

$modelOutput = (
    & $modelExe.FullName validate
) -join [Environment]::NewLine

if ($LASTEXITCODE -ne 0) {
    throw "Apple machine model validation failed."
}

Write-Host $modelOutput

if (
    $modelOutput -notmatch
    "APPLE_MACHINE_MODEL_CONTRACT_PASS"
) {
    throw "Apple machine model PASS marker missing."
}

$modelJsonText = (
    & $modelExe.FullName probe
) -join [Environment]::NewLine

$model = $modelJsonText |
    ConvertFrom-Json

if (
    $model.platform_type -ne
    "vresearch101"
) {
    throw "Wrong platform type."
}

if (
    [int]$model.platform_version -ne
    3
) {
    throw "Wrong platform version."
}

if (
    $model.board_id -ne
    "0x90"
) {
    throw "Wrong board ID."
}

if (
    [int]$model.isa -ne
    2
) {
    throw "Wrong ISA."
}

if (
    $model.udid_chip_id -ne
    "0xFE01"
) {
    throw "Wrong CPID."
}

if (
    $model.qemu_machine_model_implemented -ne
    $false
) {
    throw "QEMU Apple machine model promoted prematurely."
}

if (
    $model.guest_boot_ready -ne
    $false
) {
    throw "Windows guest boot promoted prematurely."
}

Write-Host "Canonical machine descriptor : PASS" -ForegroundColor Green
Write-Host "Premature boot claim          : BLOCKED" -ForegroundColor Green

# ------------------------------------------------------------
# 8/9 Fail-closed VM launch
# ------------------------------------------------------------

Write-Host ""
Write-Host "[8/9] Fail-closed VM launch regression..." -ForegroundColor Yellow

$vmExe = Get-ChildItem `
    $buildDir `
    -Recurse `
    -File `
    -Filter "vphone-vm-win.exe" |
    Select-Object -First 1

if (-not $vmExe) {
    throw "vphone-vm-win.exe not produced."
}

$launchOutput = @()

& $vmExe.FullName launch `
    2>&1 |
    ForEach-Object {
        $launchOutput += $_.ToString()
    }

$launchExit = $LASTEXITCODE

if ($launchExit -ne 78) {
    throw "VM launch must remain fail-closed with exit 78. Got $launchExit."
}

$launchText = (
    $launchOutput -join
    [Environment]::NewLine
)

if (
    $launchText -notmatch
    "BLOCKED:"
) {
    throw "Fail-closed launch message missing."
}

Write-Host "Fail-closed VM launch : PASS" -ForegroundColor Green

# ------------------------------------------------------------
# 9/9 Evidence
# ------------------------------------------------------------

Write-Host ""
Write-Host "[9/9] Writing exact-commit evidence..." -ForegroundColor Yellow

$evidenceDir = Join-Path `
    $repoRoot `
    "build\phase05c-apple-machine-model-evidence"

New-Item `
    -ItemType Directory `
    -Force `
    -Path $evidenceDir |
    Out-Null

$evidence = [ordered]@{
    phase = "05C"
    commit = $commit
    branch = $branch

    platform_type = "vresearch101"
    platform_version = 3
    board_id = "0x90"
    isa = 2
    udid_chip_id = "0xFE01"

    upstream_model_parity = $true
    qemu_arm64_provider = $true
    descriptor_complete = $true

    qemu_apple_machine_model_implemented = $false
    apple_virtualization_private_api_available = $false
    windows_guest_boot_ready = $false

    release_build = $true
    release_tests = $true
    fail_closed_launch = $true
}

$jsonPath = Join-Path `
    $evidenceDir `
    "phase05c-apple-machine-model-$commit.json"

$mdPath = Join-Path `
    $evidenceDir `
    "phase05c-apple-machine-model-$commit.md"

$evidence |
    ConvertTo-Json -Depth 6 |
    Set-Content `
        -Path $jsonPath `
        -Encoding UTF8

@"
# Phase 5C Apple Machine Model Foundation

Commit: $commit

Platform type: vresearch101
Platform version: 3
Board ID: 0x90
ISA: 2
CPID: 0xFE01

Upstream model parity: PASS
QEMU ARM64 provider inheritance: PASS
Machine descriptor contract: PASS
Release build: PASS
Release tests: PASS
Fail-closed launch: PASS

QEMU Apple machine implementation: NOT IMPLEMENTED
Windows guest boot: NOT CLAIMED
"@ |
    Set-Content `
        -Path $mdPath `
        -Encoding UTF8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 5C PHYSICAL WINDOWS VERIFIED PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Commit              : $commit" -ForegroundColor Green
Write-Host "vresearch101        : PASS" -ForegroundColor Green
Write-Host "PV                   : 3" -ForegroundColor Green
Write-Host "Board ID             : 0x90" -ForegroundColor Green
Write-Host "ISA                  : 2" -ForegroundColor Green
Write-Host "CPID                 : 0xFE01" -ForegroundColor Green
Write-Host "Upstream parity      : PASS" -ForegroundColor Green
Write-Host "QEMU inheritance     : PASS" -ForegroundColor Green
Write-Host "Release build        : PASS" -ForegroundColor Green
Write-Host "Release tests        : PASS" -ForegroundColor Green
Write-Host "Fail-closed launch   : PASS" -ForegroundColor Green
Write-Host ""
Write-Host "QEMU APPLE MODEL     : NOT IMPLEMENTED" -ForegroundColor Yellow
Write-Host "WINDOWS GUEST BOOT   : NOT CLAIMED" -ForegroundColor Yellow
Write-Host ""
# Phase 5C successful completion must not leak an intentionally
# nonzero native probe exit code into the parent certification gate.
$global:LASTEXITCODE = 0