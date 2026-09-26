param(
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "build\phase4d5-feasibility"
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path $repoRoot $OutputDir
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VPHONE WINDOWS PORT - PHASE 4D5 BOOT PATH FEASIBILITY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# HOST INFORMATION
# ------------------------------------------------------------

Write-Host "[1/8] Host architecture census..." -ForegroundColor Yellow

$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

$hostArchitecture = $env:PROCESSOR_ARCHITECTURE
$processArch      = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
$osArch           = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()

$virtualizationFirmwareEnabled = $null
$vmMonitorModeExtensions       = $null
$secondLevelTranslation        = $null

if ($null -ne $cpu) {
    $virtualizationFirmwareEnabled = $cpu.VirtualizationFirmwareEnabled
    $vmMonitorModeExtensions       = $cpu.VMMonitorModeExtensions
    $secondLevelTranslation        = $cpu.SecondLevelAddressTranslationExtensions
}

Write-Host "OS                  : $($os.Caption)" -ForegroundColor Cyan
Write-Host "OS Architecture     : $osArch" -ForegroundColor Cyan
Write-Host "Process Architecture: $processArch" -ForegroundColor Cyan
Write-Host "CPU                 : $($cpu.Name)" -ForegroundColor Cyan
Write-Host "Firmware Virt       : $virtualizationFirmwareEnabled" -ForegroundColor Cyan
Write-Host "VM Monitor Ext      : $vmMonitorModeExtensions" -ForegroundColor Cyan
Write-Host "SLAT                : $secondLevelTranslation" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# WINDOWS HYPERVISOR FEATURES
# ------------------------------------------------------------

Write-Host "[2/8] Windows hypervisor capability census..." -ForegroundColor Yellow

$featureNames = @(
    "Microsoft-Hyper-V-All",
    "HypervisorPlatform",
    "VirtualMachinePlatform"
)

$featureResults = @()

foreach ($name in $featureNames) {

    $state = "query-unavailable"

    try {
        $feature = Get-WindowsOptionalFeature `
            -Online `
            -FeatureName $name `
            -ErrorAction Stop

        $state = [string]$feature.State
    }
    catch {
        $state = "query-unavailable"
    }

    $featureResults += [PSCustomObject]@{
        name  = $name
        state = $state
    }

    Write-Host "$name : $state"
}

Write-Host ""

# ------------------------------------------------------------
# QEMU ARM64 RESEARCH PATH
# ------------------------------------------------------------

Write-Host "[3/8] ARM64 execution tooling census..." -ForegroundColor Yellow

$qemuCandidates = @(
    (Get-Command "qemu-system-aarch64.exe" -ErrorAction SilentlyContinue),
    (Get-Command "qemu-system-aarch64" -ErrorAction SilentlyContinue)
) | Where-Object { $null -ne $_ } | Select-Object -Unique

$qemuPath = $null
$qemuVersion = $null
$qemuVirtMachine = $false

if (@($qemuCandidates).Count -gt 0) {

    $qemuPath = @($qemuCandidates)[0].Source

    try {
        $qemuVersion = (& $qemuPath --version 2>&1 | Select-Object -First 1).ToString()
    }
    catch {
        $qemuVersion = "version-query-failed"
    }

    try {
        $machineText = (& $qemuPath -machine help 2>&1 | Out-String)

        if ($machineText -match "(?m)^\s*virt\s") {
            $qemuVirtMachine = $true
        }
    }
    catch {
        $qemuVirtMachine = $false
    }

    Write-Host "QEMU ARM64 : FOUND" -ForegroundColor Green
    Write-Host "Path       : $qemuPath" -ForegroundColor Cyan
    Write-Host "Version    : $qemuVersion" -ForegroundColor Cyan
    Write-Host "virt model : $qemuVirtMachine" -ForegroundColor Cyan
}
else {
    Write-Host "QEMU ARM64 : NOT INSTALLED" -ForegroundColor Yellow
}

Write-Host ""

# ------------------------------------------------------------
# VERIFY CURRENT WINDOWS RUNTIME IS STILL FAIL-CLOSED
# ------------------------------------------------------------

Write-Host "[4/8] Verifying current Windows runtime boundary..." -ForegroundColor Yellow

$backendFile = Join-Path $repoRoot "windows\src\backend_stub.cpp"

if (-not (Test-Path $backendFile)) {
    throw "windows/src/backend_stub.cpp missing."
}

$backendSource = Get-Content $backendFile -Raw

$requiredBackendMarkers = @(
    "windows-research-stub",
    "Windows VM runtime has not passed Phase 5 boot feasibility",
    "return 78"
)

foreach ($marker in $requiredBackendMarkers) {

    if ($backendSource -notmatch [regex]::Escape($marker)) {
        throw "Expected fail-closed backend marker missing: $marker"
    }

    Write-Host "$marker : VERIFIED" -ForegroundColor Green
}

Write-Host ""
Write-Host "Native Windows boot runtime is correctly BLOCKED." -ForegroundColor Green
Write-Host ""

# ------------------------------------------------------------
# INVENTORY APPLE BOOT REQUIREMENTS
# ------------------------------------------------------------

Write-Host "[5/8] Mapping Apple VM boot requirements..." -ForegroundColor Yellow

$referenceFile = Join-Path `
    $repoRoot `
    "Research\VPhoneVirtualMachineRefactored.swift"

if (-not (Test-Path $referenceFile)) {
    throw "Boot-path reference implementation missing."
}

$referenceSource = Get-Content $referenceFile -Raw

$requirements = @(
    [PSCustomObject]@{
        id = "hardware_model"
        token = "VZMacHardwareModel"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "machine_identifier"
        token = "VZMacMachineIdentifier"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "nvram_aux_storage"
        token = "VZMacAuxiliaryStorage"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "rom_bootloader"
        token = "VZMacOSBootLoader"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "graphics"
        token = "VZMacGraphicsDeviceConfiguration"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "disk_transport"
        token = "VZDiskImageStorageDeviceAttachment"
        windows_status = "host-storage-foundation-ready"
    },
    [PSCustomObject]@{
        id = "virtio_block"
        token = "VZVirtioBlockDeviceConfiguration"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "virtio_network"
        token = "VZVirtioNetworkDeviceConfiguration"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "pl011_serial"
        token = "_VZPL011SerialPortConfiguration"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "virtio_socket"
        token = "VZVirtioSocketDeviceConfiguration"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "touch_input"
        token = "_VZUSBTouchScreenConfiguration"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "synthetic_battery"
        token = "_VZMacSyntheticBatterySource"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "sep_coprocessor"
        token = "_VZSEPCoprocessorConfiguration"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "gdb_debug_stub"
        token = "_VZGDBDebugStubConfiguration"
        windows_status = "not-implemented"
    },
    [PSCustomObject]@{
        id = "dfu_start_mode"
        token = "_setForceDFU"
        windows_status = "not-implemented"
    }
)

foreach ($item in $requirements) {

    $present = $referenceSource -match [regex]::Escape($item.token)

    $item | Add-Member `
        -NotePropertyName upstream_present `
        -NotePropertyValue $present

    if (-not $present) {
        throw "Expected upstream boot requirement missing: $($item.token)"
    }

    Write-Host (
        "{0,-24} upstream=PRESENT windows={1}" -f `
        $item.id,
        $item.windows_status
    )
}

Write-Host ""

# ------------------------------------------------------------
# CURRENT NATIVE WINDOWS CAPABILITIES
# ------------------------------------------------------------

Write-Host "[6/8] Reading native Windows capability probe..." -ForegroundColor Yellow

$buildCandidates = Get-ChildItem `
    -Path (Join-Path $repoRoot "build") `
    -Filter "vphone-vm-win.exe" `
    -File `
    -Recurse `
    -ErrorAction SilentlyContinue

$vmExe = $buildCandidates |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$nativeCapabilities = $null

if ($null -ne $vmExe) {

    try {
        $capText = & $vmExe.FullName --capabilities

        if ($LASTEXITCODE -eq 0) {
            $nativeCapabilities = ($capText -join "`n") | ConvertFrom-Json
            Write-Host "Native Windows capability probe : PASS" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Native capability executable present but probe failed." -ForegroundColor Yellow
    }
}
else {
    Write-Host "No prior vphone-vm-win.exe build found. Census continues." -ForegroundColor Yellow
}

Write-Host ""

# ------------------------------------------------------------
# FEASIBILITY CLASSIFICATION
# ------------------------------------------------------------

Write-Host "[7/8] Classifying Windows boot research path..." -ForegroundColor Yellow

$executionPath = "no-arm64-runtime-tool-detected"

if ($null -ne $qemuPath) {
    $executionPath = "qemu-tcg-arm64-research-candidate"
}

if (
    $osArch -eq "Arm64" -and
    $null -ne $qemuPath
) {
    $executionPath = "windows-arm64-qemu-hypervisor-research-candidate"
}

$runtimeStatus = "not-implemented"
$bootClaim = "NO-BOOT-CLAIM"

Write-Host "Execution research path : $executionPath" -ForegroundColor Cyan
Write-Host "Windows runtime status  : $runtimeStatus" -ForegroundColor Yellow
Write-Host "Boot claim              : $bootClaim" -ForegroundColor Yellow

Write-Host ""

# ------------------------------------------------------------
# EVIDENCE
# ------------------------------------------------------------

Write-Host "[8/8] Writing evidence..." -ForegroundColor Yellow

$gitSha = (git rev-parse HEAD).Trim()
$gitBranch = (git branch --show-current).Trim()

$evidence = [ordered]@{

    phase = "4D5"

    gate = "boot-path-feasibility"

    commit = $gitSha

    branch = $gitBranch

    timestamp_utc = [DateTime]::UtcNow.ToString("o")

    host = [ordered]@{
        os = $os.Caption
        os_architecture = $osArch
        process_architecture = $processArch
        environment_architecture = $hostArchitecture
        cpu = $cpu.Name
        virtualization_firmware_enabled = $virtualizationFirmwareEnabled
        vm_monitor_mode_extensions = $vmMonitorModeExtensions
        second_level_address_translation = $secondLevelTranslation
    }

    windows_features = $featureResults

    qemu = [ordered]@{
        available = ($null -ne $qemuPath)
        path = $qemuPath
        version = $qemuVersion
        virt_machine_available = $qemuVirtMachine
    }

    inherited_phase4d4c = [ordered]@{
        fixed_vhd_conversion = "supported"
        fixed_vhd_readonly_attach = "supported"
        aggregate_attach_convert = "supported"
        physical_windows_probe = "passed"
    }

    boot_requirements = $requirements

    native_probe = $nativeCapabilities

    feasibility = [ordered]@{
        execution_research_path = $executionPath
        windows_boot_runtime = $runtimeStatus
        boot_claim = $bootClaim
        current_backend_fail_closed = $true
    }

    next_gate = "phase-5-runtime-foundation"
}

$jsonPath = Join-Path $OutputDir "phase4d5-feasibility.json"

$evidence |
    ConvertTo-Json -Depth 10 |
    Set-Content `
        -Path $jsonPath `
        -Encoding utf8

$mdPath = Join-Path $OutputDir "phase4d5-feasibility.md"

$md = @"
# Phase 4D5 Boot Path Feasibility

Commit: $gitSha

Branch: $gitBranch

## Result

BOOT PATH FEASIBILITY CENSUS PASS

This is not a guest boot certification.

Current native Windows backend remains deliberately fail-closed.

## Host

OS: $($os.Caption)

Architecture: $osArch

CPU: $($cpu.Name)

## ARM64 execution research path

$executionPath

## Current boot status

Native Windows boot runtime: not implemented

Boot claim: none

## Inherited Phase 4D4C capability

Fixed VHD conversion: supported

Read-only fixed VHD attach: supported

Aggregate attach/convert: supported

Physical Windows probe: passed

## Next

Phase 5 runtime foundation must implement the execution and machine-model
boundary before any Windows guest boot claim is permitted.
"@

[System.IO.File]::WriteAllText(
    $mdPath,
    $md,
    [System.Text.UTF8Encoding]::new($false)
)

if (-not (Test-Path $jsonPath)) {
    throw "Feasibility JSON was not produced."
}

if (-not (Test-Path $mdPath)) {
    throw "Feasibility report was not produced."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 4D5 BOOT PATH FEASIBILITY CENSUS PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Evidence JSON : $jsonPath" -ForegroundColor Green
Write-Host "Evidence MD   : $mdPath" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT: No Windows guest boot claim has been made." -ForegroundColor Yellow
Write-Host "NEXT: Phase 5 runtime foundation." -ForegroundColor Cyan