param(
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

Set-Location $repoRoot
[Environment]::CurrentDirectory = $repoRoot

if (
    [string]::IsNullOrWhiteSpace(
        $OutputDir
    )
) {
    $OutputDir = Join-Path `
        $repoRoot `
        "build\phase05b-arm64-execution-provider-evidence"
}
elseif (
    -not [System.IO.Path]::
        IsPathRooted($OutputDir)
) {
    $OutputDir = Join-Path `
        $repoRoot `
        $OutputDir
}

New-Item `
    -ItemType Directory `
    -Force `
    -Path $OutputDir |
    Out-Null

$branch = (
    git branch --show-current
).Trim()

$head = (
    git rev-parse HEAD
).Trim()

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VPHONE WINDOWS PORT - PHASE 5B VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Branch : $branch" -ForegroundColor Cyan
Write-Host "HEAD   : $head" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/8] Windows preflight..." -ForegroundColor Yellow

& "$PSScriptRoot\windows-preflight.ps1"

if ($LASTEXITCODE -ne 0) {
    throw "Windows preflight failed."
}

Write-Host ""
Write-Host "[2/8] Resolve ARM64 provider..." -ForegroundColor Yellow

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
    throw "qemu-system-aarch64.exe is missing."
}

$qemuDir = Split-Path `
    $qemuPath `
    -Parent

if (
    ($env:Path -split ";") -notcontains
    $qemuDir
) {
    $env:Path =
        "$qemuDir;$env:Path"
}

Write-Host "Provider: $qemuPath" -ForegroundColor Green

Write-Host ""
Write-Host "[3/8] Select CMake generator..." -ForegroundColor Yellow

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
    throw "vswhere.exe not found."
}

$vsRaw = & $vswhere `
    -latest `
    -products '*' `
    -requires Microsoft.Component.MSBuild `
    -format json `
    -utf8

$vsInstances = @(
    ($vsRaw -join [Environment]::NewLine) |
    ConvertFrom-Json
)

$vsInstance = $vsInstances |
    Select-Object -First 1

if (-not $vsInstance) {
    throw "No usable Visual Studio installation found."
}

$vsMajor = [int](
    $vsInstance.installationVersion.
        Split('.')[0]
)

switch ($vsMajor) {
    { $_ -ge 18 } {
        $cmakeGenerator =
            "Visual Studio 18 2026"
        break
    }

    17 {
        $cmakeGenerator =
            "Visual Studio 17 2022"
        break
    }

    default {
        throw "Unsupported Visual Studio major: $vsMajor"
    }
}

if (
    $cmakeHelp -notmatch
    [regex]::Escape(
        $cmakeGenerator
    )
) {
    throw "CMake does not support generator '$cmakeGenerator'."
}

Write-Host "Generator: $cmakeGenerator" -ForegroundColor Green

Write-Host ""
Write-Host "[4/8] Configure + Release build..." -ForegroundColor Yellow

$buildDir = Join-Path `
    $repoRoot `
    "build\windows-phase05b"

if (Test-Path $buildDir) {
    Remove-Item `
        $buildDir `
        -Recurse `
        -Force
}

cmake `
    -S ".\windows" `
    -B $buildDir `
    -G $cmakeGenerator `
    -A x64

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5B CMake configure failed."
}

cmake `
    --build $buildDir `
    --config Release `
    --parallel

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5B Release build failed."
}

Write-Host ""
Write-Host "[5/8] Complete Release test suite..." -ForegroundColor Yellow

ctest `
    --test-dir $buildDir `
    -C Release `
    --output-on-failure

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5B Release tests failed."
}

Write-Host ""
Write-Host "[6/8] Native provider probe..." -ForegroundColor Yellow

$providerExe = Get-ChildItem `
    $buildDir `
    -Filter "vphone-arm64-provider-win.exe" `
    -File `
    -Recurse |
    Select-Object -First 1

if (-not $providerExe) {
    throw "ARM64 provider executable was not produced."
}

$providerJson = (
    & $providerExe.FullName probe
) -join [Environment]::NewLine

if ($LASTEXITCODE -ne 0) {
    throw "ARM64 provider probe failed."
}

$provider = $providerJson |
    ConvertFrom-Json

if (
    $provider.available -ne $true
) {
    throw "ARM64 execution provider is unavailable."
}

if (
    $provider.provider -ne "qemu-tcg" -and
    $provider.provider -ne "windows-arm64-native"
) {
    throw "Unexpected ARM64 provider: $($provider.provider)"
}

if (
    $provider.apple_machine_model_implemented -ne
    $false
) {
    throw "Apple machine model promoted prematurely."
}

if (
    $provider.windows_guest_boot_ready -ne
    $false
) {
    throw "Windows guest boot promoted prematurely."
}

Write-Host $providerJson
Write-Host "Provider contract: PASS" -ForegroundColor Green

Write-Host ""
Write-Host "[7/8] QEMU ARM64 process startup smoke..." -ForegroundColor Yellow

$qemuArgs = @(
    "-machine", "virt",
    "-cpu", "cortex-a57",
    "-accel", "tcg",
    "-m", "128M",
    "-nodefaults",
    "-display", "none",
    "-serial", "none",
    "-monitor", "none"
)

$process = Start-Process `
    -FilePath $qemuPath `
    -ArgumentList $qemuArgs `
    -PassThru `
    -WindowStyle Hidden

Start-Sleep -Seconds 2

$process.Refresh()

if ($process.HasExited) {
    throw "QEMU ARM64 provider exited prematurely with code $($process.ExitCode)."
}

Stop-Process `
    -Id $process.Id `
    -Force

$process.WaitForExit()

Write-Host "QEMU ARM64 startup smoke: PASS" -ForegroundColor Green

Write-Host ""
Write-Host "[8/8] Writing exact-commit evidence..." -ForegroundColor Yellow

$evidence = [ordered]@{
    phase = "05B"
    commit = $head
    branch = $branch
    provider = $provider.provider
    host_architecture = $provider.host_architecture
    provider_available = $provider.available
    qemu_present = $provider.qemu_present
    qemu_virt_machine = $provider.qemu_virt_machine
    qemu_tcg_accelerator = $provider.qemu_tcg_accelerator
    provider_startup_smoke = $true
    apple_machine_model_implemented = $false
    windows_guest_boot_ready = $false
}

$jsonPath = Join-Path `
    $OutputDir `
    "phase05b-arm64-provider-$head.json"

$mdPath = Join-Path `
    $OutputDir `
    "phase05b-arm64-provider-$head.md"

$evidence |
    ConvertTo-Json -Depth 5 |
    Set-Content `
        -Path $jsonPath `
        -Encoding UTF8

@"
# Phase 5B ARM64 Execution Provider

Commit: $head

Provider: $($provider.provider)

Host architecture: $($provider.host_architecture)

QEMU present: $($provider.qemu_present)

QEMU virt machine: $($provider.qemu_virt_machine)

QEMU TCG accelerator: $($provider.qemu_tcg_accelerator)

Provider startup smoke: PASS

Apple machine model: NOT IMPLEMENTED

Windows guest boot: NOT CLAIMED
"@ |
    Set-Content `
        -Path $mdPath `
        -Encoding UTF8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 5B ARM64 EXECUTION PROVIDER VERIFIED PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Commit               : $head" -ForegroundColor Green
Write-Host "Release build         : PASS" -ForegroundColor Green
Write-Host "Release tests         : PASS" -ForegroundColor Green
Write-Host "Provider contract     : PASS" -ForegroundColor Green
Write-Host "QEMU ARM64 provider   : PASS" -ForegroundColor Green
Write-Host "virt machine          : PASS" -ForegroundColor Green
Write-Host "TCG accelerator       : PASS" -ForegroundColor Green
Write-Host "Provider startup      : PASS" -ForegroundColor Green
Write-Host "Apple machine model   : NOT IMPLEMENTED" -ForegroundColor Yellow
Write-Host "Windows guest boot    : NOT CLAIMED" -ForegroundColor Yellow
Write-Host ""