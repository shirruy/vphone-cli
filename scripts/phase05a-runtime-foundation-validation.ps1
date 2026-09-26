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

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "build\phase05a-runtime-foundation-evidence"
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path $repoRoot $OutputDir
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$branch = (git branch --show-current).Trim()
$head   = (git rev-parse HEAD).Trim()

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VPHONE WINDOWS PORT - PHASE 5A VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Branch : $branch" -ForegroundColor Cyan
Write-Host "HEAD   : $head" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/6] Windows preflight..." -ForegroundColor Yellow

& "$PSScriptRoot\windows-preflight.ps1"

if ($LASTEXITCODE -ne 0) {
    throw "Windows preflight failed."
}

Write-Host ""
Write-Host "[2/6] Clean Phase 5A configure..." -ForegroundColor Yellow

$buildDir = Join-Path $repoRoot "build\windows-phase05a"

if (Test-Path $buildDir) {
    Remove-Item $buildDir -Recurse -Force
}

cmake `
    -S ".\windows" `
    -B $buildDir `
    -G "Visual Studio 17 2022" `
    -A x64

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5A CMake configure failed."
}

Write-Host ""
Write-Host "[3/6] Release build..." -ForegroundColor Yellow

cmake `
    --build $buildDir `
    --config Release `
    --parallel

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5A Release build failed."
}

Write-Host ""
Write-Host "[4/6] Release test suite..." -ForegroundColor Yellow

ctest `
    --test-dir $buildDir `
    -C Release `
    --output-on-failure

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5A Release tests failed."
}

Write-Host ""
Write-Host "[5/6] Runtime foundation + fail-closed boundary..." -ForegroundColor Yellow

$vmExe = Get-ChildItem `
    $buildDir `
    -Filter "vphone-vm-win.exe" `
    -File `
    -Recurse |
    Select-Object -First 1

if (-not $vmExe) {
    throw "vphone-vm-win.exe was not produced."
}

$runtimeText = (
    & $vmExe.FullName runtime-foundation
) -join [Environment]::NewLine

if ($LASTEXITCODE -ne 0) {
    throw "runtime-foundation probe failed."
}

$runtime = $runtimeText | ConvertFrom-Json

if ([string]::IsNullOrWhiteSpace($runtime.provider)) {
    throw "Runtime provider classification missing."
}

if ([string]::IsNullOrWhiteSpace($runtime.host_architecture)) {
    throw "Host architecture classification missing."
}

if ($runtime.apple_machine_model_implemented -ne $false) {
    throw "Apple machine model promoted without implementation proof."
}

if ($runtime.boot_ready -ne $false) {
    throw "Windows guest boot promoted prematurely."
}

$launchOutput = (
    & $vmExe.FullName launch 2>&1
) -join [Environment]::NewLine

$launchExit = $LASTEXITCODE

if ($launchExit -ne 78) {
    throw "Expected fail-closed launch exit 78, received $launchExit."
}

if (
    $launchOutput -notmatch
    "Windows VM runtime has not passed Phase 5 boot feasibility"
) {
    throw "Expected fail-closed launch marker missing."
}

$capText = (
    & $vmExe.FullName --capabilities
) -join [Environment]::NewLine

if ($LASTEXITCODE -ne 0) {
    throw "Capability probe failed."
}

$cap = $capText | ConvertFrom-Json

if ($cap.backend -ne "windows-research-stub") {
    throw "Backend promoted prematurely."
}

if ($cap.persistent_storage -ne "supported") {
    throw "Inherited persistent storage capability regressed."
}

if ($cap.apple_machine_model -eq "supported") {
    throw "Apple machine model incorrectly reported as supported."
}

Write-Host ""
Write-Host "Provider          : $($runtime.provider)" -ForegroundColor Cyan
Write-Host "Host architecture : $($runtime.host_architecture)" -ForegroundColor Cyan
Write-Host "QEMU ARM64        : $($runtime.qemu_system_aarch64_present)" -ForegroundColor Cyan
Write-Host "ARM64 candidate   : $($runtime.arm64_execution_provider_detected)" -ForegroundColor Cyan
Write-Host "Apple model       : $($runtime.apple_machine_model_implemented)" -ForegroundColor Cyan
Write-Host "Boot ready        : $($runtime.boot_ready)" -ForegroundColor Cyan
Write-Host "Launch exit       : $launchExit" -ForegroundColor Cyan

Write-Host ""
Write-Host "[6/6] Writing exact-commit evidence..." -ForegroundColor Yellow

$evidence = [ordered]@{
    phase = "5A"
    gate = "windows-runtime-foundation-contract"
    repository_commit = $head
    branch = $branch
    timestamp_utc = [DateTime]::UtcNow.ToString("o")

    physical_windows = "PASS"
    release_build = "PASS"
    release_tests = "PASS"

    runtime = [ordered]@{
        provider = $runtime.provider
        host_architecture = $runtime.host_architecture
        provider_path = $runtime.provider_path

        qemu_system_aarch64_present =
            $runtime.qemu_system_aarch64_present

        arm64_execution_provider_detected =
            $runtime.arm64_execution_provider_detected

        apple_machine_model_implemented =
            $runtime.apple_machine_model_implemented

        boot_ready =
            $runtime.boot_ready
    }

    backend = [ordered]@{
        name = $cap.backend
        persistent_storage = $cap.persistent_storage
        apple_machine_model = $cap.apple_machine_model
        fail_closed_launch = "PASS"
        launch_exit_code = $launchExit
    }

    boot_claim = "NOT_CLAIMED"

    next_gate =
        "PHASE_5B_ARM64_EXECUTION_PROVIDER"
}

$jsonPath = Join-Path $OutputDir "phase05a-runtime-foundation.json"

$evidence |
    ConvertTo-Json -Depth 12 |
    Set-Content `
        -Path $jsonPath `
        -Encoding utf8

$runtimeText |
    Set-Content `
        -Path (
            Join-Path $OutputDir "runtime-foundation-probe.json"
        ) `
        -Encoding utf8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 5A PHYSICAL WINDOWS VERIFIED PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Commit             : $head" -ForegroundColor Green
Write-Host "Release build       : PASS" -ForegroundColor Green
Write-Host "Release tests       : PASS" -ForegroundColor Green
Write-Host "Runtime foundation  : PASS" -ForegroundColor Green
Write-Host "Fail-closed launch  : PASS" -ForegroundColor Green
Write-Host "Physical Windows    : PASS" -ForegroundColor Green
Write-Host "Windows guest boot  : NOT CLAIMED" -ForegroundColor Yellow
Write-Host ""