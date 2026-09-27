$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ================================================================
# VPHONE WINDOWS PORT
# PHASE 5D EXECUTION FOUNDATION VALIDATION
#
# Tests:
#   - Certified Phase 5C ancestry
#   - Windows physical preflight
#   - QEMU ARM64 provider presence
#   - QEMU binary hash
#   - QEMU virt machine
#   - QEMU TCG accelerator
#   - Complete Release build
#   - Complete Release CTest suite
#   - Phase 5C machine-model contract inheritance
#   - Physical QEMU process lifecycle
#   - Existing Apple guest launch remains fail-closed
#
# Explicitly NOT certified:
#   - Apple guest boot
#   - vresearch101 QEMU machine implementation
#   - graphical guest
# ================================================================

$repoRoot = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

Set-Location $repoRoot
[Environment]::CurrentDirectory = $repoRoot

$expectedBranch =
    "phase/05d-execution-foundation"

$certifiedPhase5CSHA =
    "684df0c3124434dd22fcbde9230df20407c6e21f"


function Invoke-GitAncestorCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Ancestor,

        [Parameter(Mandatory = $true)]
        [string]$Descendant
    )

    git merge-base `
        --is-ancestor `
        $Ancestor `
        $Descendant

    $exit = $LASTEXITCODE

    if ($exit -eq 0) {
        return $true
    }

    if ($exit -eq 1) {
        return $false
    }

    throw "git merge-base failed with exit code $exit."
}


Write-Host ""
Write-Host `
    "============================================================" `
    -ForegroundColor Cyan

Write-Host `
    " VPHONE WINDOWS PORT - PHASE 5D PHYSICAL VALIDATION" `
    -ForegroundColor Cyan

Write-Host `
    "============================================================" `
    -ForegroundColor Cyan

Write-Host ""


# ================================================================
# 1/10 Repository + lineage
# ================================================================

Write-Host `
    "[1/10] Repository and certified lineage..." `
    -ForegroundColor Yellow


$branch = [string](
    git branch --show-current
)

if ($LASTEXITCODE -ne 0) {
    throw "Unable to resolve branch."
}

$branch = $branch.Trim()


$commit = [string](
    git rev-parse HEAD
)

if ($LASTEXITCODE -ne 0) {
    throw "Unable to resolve HEAD."
}

$commit =
    $commit.Trim().ToLowerInvariant()


if ($branch -ne $expectedBranch) {
    throw @"
Wrong Phase 5D branch.

Expected:
$expectedBranch

Actual:
$branch
"@
}


if (
    -not (
        Invoke-GitAncestorCheck `
            -Ancestor $certifiedPhase5CSHA `
            -Descendant $commit
    )
) {
    throw @"
Phase 5D does not descend from certified Phase 5C.

Certified Phase 5C:
$certifiedPhase5CSHA

Current HEAD:
$commit
"@
}


Write-Host `
    "Branch            : $branch" `
    -ForegroundColor Green

Write-Host `
    "HEAD              : $commit" `
    -ForegroundColor Green

Write-Host `
    "Phase 5C ancestry : PASS" `
    -ForegroundColor Green


# ================================================================
# 2/10 Windows preflight
# ================================================================

Write-Host ""
Write-Host `
    "[2/10] Windows physical preflight..." `
    -ForegroundColor Yellow


& "$PSScriptRoot\windows-preflight.ps1"

if ($LASTEXITCODE -ne 0) {
    throw "Windows preflight failed."
}


Write-Host `
    "Windows preflight : PASS" `
    -ForegroundColor Green


# ================================================================
# 3/10 Locate and fingerprint QEMU
# ================================================================

Write-Host ""
Write-Host `
    "[3/10] Locating ARM64 execution provider..." `
    -ForegroundColor Yellow


$qemuCommand =
    Get-Command `
        "qemu-system-aarch64.exe" `
        -ErrorAction SilentlyContinue


$qemuPath = $null


if ($qemuCommand) {

    $qemuPath =
        $qemuCommand.Source
}
else {

    $candidate =
        Join-Path `
            $env:ProgramFiles `
            "qemu\qemu-system-aarch64.exe"

    if (Test-Path $candidate) {
        $qemuPath =
            $candidate
    }
}


if (-not $qemuPath) {
    throw @"
QEMU ARM64 provider is missing.

Expected:
qemu-system-aarch64.exe
"@
}


$qemuPath =
    (Resolve-Path $qemuPath).Path


$qemuVersionLines = @(
    & $qemuPath --version
)

if ($LASTEXITCODE -ne 0) {
    throw "Unable to execute qemu-system-aarch64 --version."
}


if ($qemuVersionLines.Count -eq 0) {
    throw "QEMU version output was empty."
}


$qemuVersion =
    [string]$qemuVersionLines[0]


$qemuHash =
    (
        Get-FileHash `
            -Path $qemuPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()


Write-Host `
    "QEMU path    : $qemuPath" `
    -ForegroundColor Cyan

Write-Host `
    "QEMU version : $qemuVersion" `
    -ForegroundColor Cyan

Write-Host `
    "QEMU SHA256  : $qemuHash" `
    -ForegroundColor Cyan

Write-Host `
    "ARM64 provider fingerprint : PASS" `
    -ForegroundColor Green


# ================================================================
# 4/10 Provider capability gate
# ================================================================

Write-Host ""
Write-Host `
    "[4/10] Verifying QEMU virt + TCG capability..." `
    -ForegroundColor Yellow


$machines = (
    & $qemuPath -machine help
) -join [Environment]::NewLine

if ($LASTEXITCODE -ne 0) {
    throw "Unable to query QEMU machine list."
}


$accelerators = (
    & $qemuPath -accel help
) -join [Environment]::NewLine

if ($LASTEXITCODE -ne 0) {
    throw "Unable to query QEMU accelerator list."
}


if (
    $machines -notmatch
    '(?m)^\s*virt\s'
) {
    throw "QEMU ARM64 virt machine is unavailable."
}


if (
    $accelerators -notmatch
    '(?m)^\s*tcg\s*$'
) {
    throw "QEMU TCG accelerator is unavailable."
}


Write-Host `
    "QEMU virt machine : PASS" `
    -ForegroundColor Green

Write-Host `
    "QEMU TCG          : PASS" `
    -ForegroundColor Green


# ================================================================
# 5/10 Select Visual Studio generator
# ================================================================

Write-Host ""
Write-Host `
    "[5/10] Selecting Visual Studio generator..." `
    -ForegroundColor Yellow


$cmakeHelp = (
    & cmake --help 2>&1
) -join [Environment]::NewLine

if ($LASTEXITCODE -ne 0) {
    throw "Unable to execute CMake."
}


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


$vswhere =
    $vswhereCandidates |
        Where-Object {
            $_ -and (Test-Path $_)
        } |
        Select-Object -First 1


if (-not $vswhere) {
    throw "vswhere.exe is missing."
}


$vsJson = & $vswhere `
    -latest `
    -products '*' `
    -requires Microsoft.Component.MSBuild `
    -format json `
    -utf8


if ($LASTEXITCODE -ne 0) {
    throw "vswhere failed."
}


$instances = @(
    ($vsJson -join [Environment]::NewLine) |
        ConvertFrom-Json
)


$instance =
    $instances |
        Select-Object -First 1


if (-not $instance) {
    throw "No Visual Studio installation with MSBuild found."
}


$major =
    [int](
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

        throw "Unsupported Visual Studio major version: $major"
    }
}


if (
    $cmakeHelp -notmatch
    [regex]::Escape($generator)
) {
    throw "CMake generator unavailable: $generator"
}


Write-Host `
    "Generator : $generator" `
    -ForegroundColor Green


# ================================================================
# 6/10 Complete clean Release build
# ================================================================

Write-Host ""
Write-Host `
    "[6/10] Clean Release build..." `
    -ForegroundColor Yellow


$buildDir =
    Join-Path `
        $repoRoot `
        "build\windows-phase05d"


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
    throw "Phase 5D CMake configuration failed."
}


cmake `
    --build $buildDir `
    --config Release `
    --parallel


if ($LASTEXITCODE -ne 0) {
    throw "Phase 5D Release build failed."
}


Write-Host `
    "Release build : PASS" `
    -ForegroundColor Green


# ================================================================
# 7/10 Complete Release tests
# ================================================================

Write-Host ""
Write-Host `
    "[7/10] Complete Release CTest suite..." `
    -ForegroundColor Yellow


ctest `
    --test-dir $buildDir `
    -C Release `
    --output-on-failure


if ($LASTEXITCODE -ne 0) {
    throw "Phase 5D Release tests failed."
}


Write-Host `
    "Complete Release tests : PASS" `
    -ForegroundColor Green


# ================================================================
# 8/10 Inherited Phase 5C machine-model contract
# ================================================================

Write-Host ""
Write-Host `
    "[8/10] Revalidating Phase 5C Apple machine boundary..." `
    -ForegroundColor Yellow


$modelExe =
    Get-ChildItem `
        $buildDir `
        -Recurse `
        -File `
        -Filter "vphone-apple-machine-win.exe" |
        Select-Object -First 1


if (-not $modelExe) {
    throw "vphone-apple-machine-win.exe was not produced."
}


$modelOutput = @(
    & $modelExe.FullName validate
)


if ($LASTEXITCODE -ne 0) {
    throw "Inherited Apple machine-model validation failed."
}


$modelText =
    $modelOutput -join [Environment]::NewLine


if (
    $modelText -notmatch
    'APPLE_MACHINE_MODEL_CONTRACT_PASS'
) {
    throw "Apple machine-model PASS marker missing."
}


$modelJsonText = (
    & $modelExe.FullName probe
) -join [Environment]::NewLine


if ($LASTEXITCODE -ne 0) {
    throw "Apple machine model probe failed."
}


$model =
    $modelJsonText |
        ConvertFrom-Json


if ($model.platform_type -ne "vresearch101") {
    throw "Wrong inherited platform type."
}

if ([int]$model.platform_version -ne 3) {
    throw "Wrong inherited platform version."
}

if ($model.board_id -ne "0x90") {
    throw "Wrong inherited board ID."
}

if ([int]$model.isa -ne 2) {
    throw "Wrong inherited ISA."
}

if ($model.udid_chip_id -ne "0xFE01") {
    throw "Wrong inherited CPID."
}


if (
    $model.qemu_machine_model_implemented -ne
    $false
) {
    throw @"
Safety violation.

Phase 5D must not silently promote
qemu_machine_model_implemented.
"@
}


if (
    $model.guest_boot_ready -ne
    $false
) {
    throw @"
Safety violation.

Phase 5D must not silently promote
guest_boot_ready.
"@
}


Write-Host `
    "vresearch101 descriptor : PASS" `
    -ForegroundColor Green

Write-Host `
    "Premature boot claim    : BLOCKED" `
    -ForegroundColor Green


# ================================================================
# 9/10 PHYSICAL QEMU EXECUTION LIFECYCLE
# ================================================================

Write-Host ""
Write-Host `
    "[9/10] Physical ARM64 process lifecycle probe..." `
    -ForegroundColor Yellow


$probeDir =
    Join-Path `
        $buildDir `
        "phase05d-lifecycle"


New-Item `
    -ItemType Directory `
    -Force `
    -Path $probeDir |
    Out-Null


$stdoutPath =
    Join-Path `
        $probeDir `
        "qemu-stdout.log"


$stderrPath =
    Join-Path `
        $probeDir `
        "qemu-stderr.log"


Remove-Item `
    $stdoutPath `
    -Force `
    -ErrorAction SilentlyContinue

Remove-Item `
    $stderrPath `
    -Force `
    -ErrorAction SilentlyContinue


# IMPORTANT:
# This is intentionally NOT an Apple guest boot command.
#
# We are proving only that the Windows host can:
#   1. instantiate the selected AArch64 provider,
#   2. instantiate QEMU's generic virt machine,
#   3. initialize TCG,
#   4. remain alive under a controlled paused state,
#   5. be terminated deterministically by the harness.

$qemuArgs = @(
    "-machine", "virt",
    "-accel", "tcg",
    "-cpu", "max",
    "-m", "128M",
    "-nodefaults",
    "-display", "none",
    "-serial", "none",
    "-monitor", "none",
    "-S"
)


Write-Host `
    "Starting controlled QEMU ARM64 process..." `
    -ForegroundColor Cyan


$process = $null


try {

    $process =
        Start-Process `
            -FilePath $qemuPath `
            -ArgumentList $qemuArgs `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -PassThru


    if (-not $process) {
        throw "Start-Process did not return a process object."
    }


    Start-Sleep `
        -Milliseconds 2500


    $process.Refresh()


    if ($process.HasExited) {

        $stderr = ""

        if (Test-Path $stderrPath) {
            $stderr =
                Get-Content `
                    $stderrPath `
                    -Raw `
                    -ErrorAction SilentlyContinue
        }

        throw @"
QEMU ARM64 process exited before the health window completed.

Exit code:
$($process.ExitCode)

stderr:
$stderr
"@
    }


    Write-Host `
        "Process ID       : $($process.Id)" `
        -ForegroundColor Cyan

    Write-Host `
        "Health window    : 2500 ms" `
        -ForegroundColor Cyan

    Write-Host `
        "Observed running : PASS" `
        -ForegroundColor Green


    Stop-Process `
        -Id $process.Id `
        -Force `
        -ErrorAction Stop


    if (
        -not $process.WaitForExit(5000)
    ) {
        throw "QEMU process did not terminate within 5 seconds."
    }


    $process.Refresh()


    if (-not $process.HasExited) {
        throw "QEMU process remained alive after harness termination."
    }


    Write-Host `
        "Harness cleanup  : PASS" `
        -ForegroundColor Green
}
finally {

    if ($process) {

        try {

            $process.Refresh()

            if (-not $process.HasExited) {

                Stop-Process `
                    -Id $process.Id `
                    -Force `
                    -ErrorAction SilentlyContinue

                $null =
                    $process.WaitForExit(5000)
            }
        }
        catch {
            # Best-effort emergency cleanup only.
        }
    }
}


# ================================================================
# 10/10 Fail-closed Apple guest launch + evidence
# ================================================================

Write-Host ""
Write-Host `
    "[10/10] Fail-closed guest launch + evidence..." `
    -ForegroundColor Yellow


$vmExe =
    Get-ChildItem `
        $buildDir `
        -Recurse `
        -File `
        -Filter "vphone-vm-win.exe" |
        Select-Object -First 1


if (-not $vmExe) {
    throw "vphone-vm-win.exe was not produced."
}


$launchOutput = @()


& $vmExe.FullName launch `
    2>&1 |
    ForEach-Object {
        $launchOutput +=
            $_.ToString()
    }


$launchExit =
    $LASTEXITCODE


if ($launchExit -ne 78) {
    throw @"
Guest launch safety regression.

Expected fail-closed exit:
78

Actual:
$launchExit
"@
}


$launchText =
    $launchOutput -join [Environment]::NewLine


if (
    $launchText -notmatch
    'BLOCKED:'
) {
    throw "Expected BLOCKED launch marker is missing."
}


Write-Host `
    "Apple guest launch : FAIL-CLOSED PASS" `
    -ForegroundColor Green


# ------------------------------------------------
# Machine-readable evidence
# ------------------------------------------------

$evidenceDir =
    Join-Path `
        $repoRoot `
        "build\phase05d-execution-foundation-evidence"


if (Test-Path $evidenceDir) {

    Remove-Item `
        $evidenceDir `
        -Recurse `
        -Force
}


New-Item `
    -ItemType Directory `
    -Force `
    -Path $evidenceDir |
    Out-Null


$os =
    Get-CimInstance `
        Win32_OperatingSystem


$cpu =
    Get-CimInstance `
        Win32_Processor |
        Select-Object -First 1


$evidence = [ordered]@{

    phase = "05D"

    gate =
        "windows-arm64-execution-foundation"

    branch =
        $branch

    tested_commit =
        $commit

    certified_phase05c =
        $certifiedPhase5CSHA

    environment = [ordered]@{

        os_caption =
            $os.Caption

        os_version =
            $os.Version

        architecture =
            $env:PROCESSOR_ARCHITECTURE

        processor =
            $cpu.Name
    }

    qemu = [ordered]@{

        executable =
            $qemuPath

        version =
            $qemuVersion

        sha256 =
            $qemuHash

        virt_machine =
            $true

        tcg_accelerator =
            $true
    }

    execution_lifecycle = [ordered]@{

        process_started =
            $true

        health_window_ms =
            2500

        observed_running =
            $true

        harness_terminated =
            $true

        guest_payload_supplied =
            $false

        apple_guest_boot_attempted =
            $false
    }

    inherited_machine_model = [ordered]@{

        platform_type =
            "vresearch101"

        platform_version =
            3

        board_id =
            "0x90"

        isa =
            2

        cpid =
            "0xFE01"

        descriptor_valid =
            $true

        qemu_apple_machine_model_implemented =
            $false

        windows_guest_boot_ready =
            $false
    }

    validation = [ordered]@{

        windows_preflight =
            $true

        release_build =
            $true

        release_tests =
            $true

        phase05c_contract =
            $true

        physical_provider_lifecycle =
            $true

        guest_launch_fail_closed =
            $true
    }

    claims = [ordered]@{

        arm64_execution_foundation =
            "PASS"

        apple_guest_boot =
            "NOT_TESTED"

        qemu_vresearch101_machine =
            "NOT_IMPLEMENTED"

        graphical_guest =
            "NOT_TESTED"
    }
}


$jsonPath =
    Join-Path `
        $evidenceDir `
        "phase05d-execution-foundation.json"


$mdPath =
    Join-Path `
        $evidenceDir `
        "phase05d-execution-foundation.md"


$evidence |
    ConvertTo-Json -Depth 10 |
    Set-Content `
        -Path $jsonPath `
        -Encoding UTF8


@"
# Phase 5D Windows Execution Foundation

Branch: $branch

Tested commit: $commit

Certified Phase 5C:
$certifiedPhase5CSHA

QEMU:
$qemuVersion

QEMU SHA256:
$qemuHash

## Executed evidence

Windows physical preflight: PASS

QEMU ARM64 executable: PASS

QEMU virt machine: PASS

QEMU TCG accelerator: PASS

Clean Release build: PASS

Complete Release CTest suite: PASS

Inherited vresearch101 descriptor: PASS

Physical QEMU process start: PASS

2500 ms running health window: PASS

Deterministic harness termination: PASS

Apple guest launch fail-closed regression: PASS

## Explicit non-claims

Apple guest boot: NOT TESTED

QEMU vresearch101 implementation: NOT IMPLEMENTED

SpringBoard: NOT TESTED

Graphical guest: NOT TESTED

Phase 5D proves the Windows ARM64 execution-process foundation only.
"@ |
    Set-Content `
        -Path $mdPath `
        -Encoding UTF8


Write-Host ""
Write-Host `
    "============================================================" `
    -ForegroundColor Green

Write-Host `
    " PHASE 5D PHYSICAL WINDOWS EXECUTION FOUNDATION PASS" `
    -ForegroundColor Green

Write-Host `
    "============================================================" `
    -ForegroundColor Green

Write-Host ""

Write-Host `
    "Branch              : $branch" `
    -ForegroundColor Green

Write-Host `
    "Tested HEAD         : $commit" `
    -ForegroundColor Green

Write-Host `
    "Certified Phase 5C  : $certifiedPhase5CSHA" `
    -ForegroundColor Green

Write-Host `
    "QEMU ARM64 provider : PASS" `
    -ForegroundColor Green

Write-Host `
    "virt + TCG          : PASS" `
    -ForegroundColor Green

Write-Host `
    "Release build       : PASS" `
    -ForegroundColor Green

Write-Host `
    "Release tests       : PASS" `
    -ForegroundColor Green

Write-Host `
    "Process lifecycle   : PASS" `
    -ForegroundColor Green

Write-Host `
    "Fail-closed launch  : PASS" `
    -ForegroundColor Green

Write-Host ""

Write-Host `
    "APPLE GUEST BOOT    : NOT TESTED" `
    -ForegroundColor Yellow

Write-Host `
    "vresearch101 QEMU   : NOT IMPLEMENTED" `
    -ForegroundColor Yellow

Write-Host ""

Write-Host `
    "Evidence:" `
    -ForegroundColor Cyan

Write-Host `
    "  $jsonPath" `
    -ForegroundColor Cyan

Write-Host `
    "  $mdPath" `
    -ForegroundColor Cyan

Write-Host ""

$global:LASTEXITCODE = 0