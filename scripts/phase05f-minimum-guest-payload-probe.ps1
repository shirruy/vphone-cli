param(
    [string]$RepoRoot =
        "C:\Users\rbjos\source\vphone-cli-windows",

    [string]$PayloadRoot =
        "$env:USERPROFILE\vphone-private\phase05f-payloads",

    [int]$RunSeconds = 20,

    [switch]$PreflightOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest


# ============================================================
# PHASE 5F - MINIMUM GUEST PAYLOAD / SERIAL PROBE
#
# This script DOES NOT download, decrypt, or extract firmware.
#
# It only accepts locally supplied payloads that the operator is
# authorized to use.
#
# Base non-SPTM payload contract:
#   bootkc
#   dtree
#   trust_cache
#   ramdisk
#
# Optional SPTM contract:
#   sptm
#   txm
#
# No full guest-boot claim is made merely from process survival
# or serial activity.
# ============================================================


$expectedBranch =
    "phase/05f-minimum-guest-payload-serial"

$certifiedPhase5e =
    "0520f14ea99d9619929c01ce47df9832bc9625a0"

$qemuBaseSHA =
    "2867d847d3471560e773120ee50c42dbcbb6d60b"

$qemuSource =
    Join-Path `
        $RepoRoot `
        "build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm"

$qemuExe =
    Join-Path `
        $qemuSource `
        "build-win\qemu-system-aarch64.exe"

$mingwBin =
    "C:\msys64\mingw64\bin"

$manifestPath =
    Join-Path `
        $PayloadRoot `
        "payload-manifest.json"

$runtimeRoot =
    Join-Path `
        $RepoRoot `
        "build\phase05f-runtime"


function Get-Sha {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $raw = [string](
        git `
            -C $Directory `
            rev-parse HEAD
    )

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to resolve Git HEAD: $Directory"
    }

    $sha =
        $raw.Trim().ToLowerInvariant()

    if ($sha -notmatch '^[0-9a-f]{40}$') {
        throw "Invalid Git SHA: [$sha]"
    }

    return $sha
}


function Convert-QemuPath {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (
        [System.IO.Path]::GetFullPath(
            $Path
        ).Replace(
            '\',
            '/'
        )
    )
}


function Resolve-PayloadPath {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if (
        [System.IO.Path]::IsPathRooted(
            $Value
        )
    ) {

        $resolved =
            [System.IO.Path]::GetFullPath(
                $Value
            )
    }
    else {

        $resolved =
            [System.IO.Path]::GetFullPath(
                (
                    Join-Path `
                        $PayloadRoot `
                        $Value
                )
            )
    }


    # ------------------------------------------------------------
    # Payloads must NEVER live inside the Git repository.
    # ------------------------------------------------------------

    $repoFull =
        (
            [System.IO.Path]::GetFullPath(
                $RepoRoot
            )
        ).TrimEnd('\') + '\'


    if (
        $resolved.StartsWith(
            $repoFull,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {

        throw @"
Payload path is inside the Git repository.

Rejected:
$resolved

Payloads must remain outside the source tree.
"@
    }


    return $resolved
}


try {

    Write-Host ""
    Write-Host `
        "============================================================" `
        -ForegroundColor Cyan

    Write-Host `
        " PHASE 5F - MINIMUM GUEST PAYLOAD / SERIAL PROBE" `
        -ForegroundColor Cyan

    Write-Host `
        "============================================================" `
        -ForegroundColor Cyan

    Write-Host ""


    # ========================================================
    # 1. VERIFY PHASE 5F LINEAGE
    # ========================================================

    Set-Location $RepoRoot


    $branch = [string](
        git branch --show-current
    )

    $branch =
        $branch.Trim()


    if ($branch -ne $expectedBranch) {

        throw @"
Wrong branch.

Expected:
$expectedBranch

Actual:
$branch
"@
    }


    $vphoneSHA =
        Get-Sha `
            -Directory $RepoRoot


    git merge-base `
        --is-ancestor `
        $certifiedPhase5e `
        $vphoneSHA


    if ($LASTEXITCODE -ne 0) {

        throw `
            "Phase 5F does not descend from certified Phase 5E."
    }


    $qemuSHA =
        Get-Sha `
            -Directory $qemuSource


    if ($qemuSHA -ne $qemuBaseSHA) {

        throw `
            "Unexpected qemu-sptm source base: $qemuSHA"
    }


    if (-not (Test-Path $qemuExe)) {
        throw "Native Windows qemu-system-aarch64.exe missing."
    }


    # ========================================================
    # 2. LOAD PAYLOAD CONTRACT
    # ========================================================

    if (-not (Test-Path $manifestPath)) {

        throw @"
Payload manifest missing:

$manifestPath
"@
    }


    $manifest =
        Get-Content `
            $manifestPath `
            -Raw |
        ConvertFrom-Json


    $mode =
        [string]$manifest.mode


    if (
        $mode -ne "nosptm" -and
        $mode -ne "sptm"
    ) {

        throw `
            "Manifest mode must be 'nosptm' or 'sptm'."
    }


    $required =
        [ordered]@{

            bootkc =
                [string]$manifest.bootkc

            dtree =
                [string]$manifest.dtree

            trust_cache =
                [string]$manifest.trust_cache

            ramdisk =
                [string]$manifest.ramdisk
        }


    if ($mode -eq "sptm") {

        $required["sptm"] =
            [string]$manifest.sptm

        $required["txm"] =
            [string]$manifest.txm
    }


    # ========================================================
    # 3. PAYLOAD PREFLIGHT
    # ========================================================

    $resolved =
        [ordered]@{}

    $missing =
        New-Object `
            System.Collections.Generic.List[string]


    Write-Host `
        "Mode : $mode" `
        -ForegroundColor Cyan

    Write-Host ""


    foreach ($entry in $required.GetEnumerator()) {

        if (
            [string]::IsNullOrWhiteSpace(
                [string]$entry.Value
            )
        ) {

            $missing.Add(
                "$($entry.Key): manifest value missing"
            )

            continue
        }


        $path =
            Resolve-PayloadPath `
                -Value $entry.Value


        if (-not (Test-Path -LiteralPath $path)) {

            $missing.Add(
                "$($entry.Key): $path"
            )

            continue
        }


        $item =
            Get-Item `
                -LiteralPath $path


        if ($item.PSIsContainer) {

            throw `
                "Payload is a directory, not a file: $path"
        }


        if ($item.Length -le 0) {

            throw `
                "Payload file is empty: $path"
        }


        $resolved[$entry.Key] =
            $path


        $hash =
            (
                Get-FileHash `
                    -LiteralPath $path `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()


        Write-Host `
            ("{0,-12} : FOUND" -f $entry.Key) `
            -ForegroundColor Green

        Write-Host `
            "  bytes  : $($item.Length)" `
            -ForegroundColor DarkGray

        Write-Host `
            "  sha256 : $hash" `
            -ForegroundColor DarkGray
    }


    if ($missing.Count -gt 0) {

        Write-Host ""
        Write-Host `
            "PAYLOAD SET IS NOT READY YET" `
            -ForegroundColor Yellow

        Write-Host ""


        foreach ($entry in $missing) {

            Write-Host `
                "  MISSING : $entry" `
                -ForegroundColor Yellow
        }


        Write-Host ""
        Write-Host `
            "Required non-SPTM payload set:" `
            -ForegroundColor Cyan

        Write-Host `
            "  bootkc" `
            -ForegroundColor Cyan

        Write-Host `
            "  dtree" `
            -ForegroundColor Cyan

        Write-Host `
            "  trust_cache" `
            -ForegroundColor Cyan

        Write-Host `
            "  ramdisk" `
            -ForegroundColor Cyan


        if ($mode -eq "sptm") {

            Write-Host `
                "  sptm" `
                -ForegroundColor Cyan

            Write-Host `
                "  txm" `
                -ForegroundColor Cyan
        }


        Write-Host ""
        Write-Host `
            "STATE : READY FOR AUTHORIZED PAYLOAD INPUT" `
            -ForegroundColor Cyan

        Write-Host `
            "GUEST EXECUTION : NOT STARTED" `
            -ForegroundColor Yellow

        Write-Host `
            "SERIAL MILESTONE: NOT TESTED" `
            -ForegroundColor Yellow

        Write-Host ""


        $global:LASTEXITCODE = 0

        return
    }


    Write-Host ""
    Write-Host `
        "Payload admission : PASS" `
        -ForegroundColor Green


    if ($PreflightOnly) {

        Write-Host ""
        Write-Host `
            "STATE : PHASE 5F PAYLOAD PREFLIGHT PASS" `
            -ForegroundColor Cyan

        Write-Host `
            "RUNTIME PROBE : NOT STARTED" `
            -ForegroundColor Yellow

        Write-Host ""


        $global:LASTEXITCODE = 0

        return
    }


    # ========================================================
    # 4. VERIFY DARWIN MACHINE REGISTRATION
    # ========================================================

    $oldPath =
        $env:PATH


    try {

        $env:PATH =
            "$mingwBin;$oldPath"


        $machines = @(
            & $qemuExe `
                -machine help
        )


        if ($LASTEXITCODE -ne 0) {
            throw "QEMU machine enumeration failed."
        }


        $machineText =
            $machines -join
            [Environment]::NewLine


        if (
            $machineText -notmatch
            '(?m)^\s*darwin(?:\s|$)'
        ) {

            throw "Darwin machine is not registered."
        }
    }
    finally {

        $env:PATH =
            $oldPath
    }


    # ========================================================
    # 5. BUILD DARWIN MACHINE ARGUMENT
    # ========================================================

    $machineParts =
        New-Object `
            System.Collections.Generic.List[string]


    $machineParts.Add(
        "darwin"
    )


    $machineParts.Add(
        "bootkc=$(
            Convert-QemuPath `
                $resolved["bootkc"]
        )"
    )


    $machineParts.Add(
        "dtree=$(
            Convert-QemuPath `
                $resolved["dtree"]
        )"
    )


    $machineParts.Add(
        "tc=$(
            Convert-QemuPath `
                $resolved["trust_cache"]
        )"
    )


    $machineParts.Add(
        "ramdisk=$(
            Convert-QemuPath `
                $resolved["ramdisk"]
        )"
    )


    if ($mode -eq "sptm") {

        $machineParts.Add(
            "sptm=$(
                Convert-QemuPath `
                    $resolved["sptm"]
            )"
        )


        $machineParts.Add(
            "txm=$(
                Convert-QemuPath `
                    $resolved["txm"]
            )"
        )
    }


    $machineArgument =
        $machineParts -join ","


    # ========================================================
    # 6. PREPARE SERIAL CAPTURE
    # ========================================================

    $runDir =
        Join-Path `
            $runtimeRoot `
            "run-current"


    if (Test-Path $runDir) {

        Remove-Item `
            $runDir `
            -Recurse `
            -Force
    }


    New-Item `
        -ItemType Directory `
        -Force `
        -Path $runDir |
        Out-Null


    $serialLog =
        Join-Path `
            $runDir `
            "serial.log"

    $stdoutLog =
        Join-Path `
            $runDir `
            "stdout.log"

    $stderrLog =
        Join-Path `
            $runDir `
            "stderr.log"

    $resultPath =
        Join-Path `
            $runDir `
            "result.json"


    $serialQemu =
        Convert-QemuPath `
            $serialLog


    # ========================================================
    # 7. START GUEST EXECUTION PROBE
    # ========================================================

    Write-Host ""
    Write-Host `
        "Starting Phase 5F guest execution probe..." `
        -ForegroundColor Yellow

    Write-Host `
        "Run window : $RunSeconds seconds" `
        -ForegroundColor Cyan

    Write-Host ""


    $arguments = @(
        "-machine",
        $machineArgument,

        "-accel",
        "tcg",

        "-display",
        "none",

        "-nodefaults",

        "-monitor",
        "none",

        "-chardev",
        "file,id=serial0,path=$serialQemu",

        "-serial",
        "chardev:serial0"
    )


    $oldPath =
        $env:PATH

    $process =
        $null


    try {

        $env:PATH =
            "$mingwBin;$oldPath"


        $process =
            Start-Process `
                -FilePath $qemuExe `
                -ArgumentList $arguments `
                -RedirectStandardOutput $stdoutLog `
                -RedirectStandardError $stderrLog `
                -PassThru


        if ($null -eq $process) {
            throw "QEMU process was not created."
        }


        $deadline =
            (Get-Date).AddSeconds(
                $RunSeconds
            )


        while (
            (Get-Date) -lt $deadline
        ) {

            $process.Refresh()


            if ($process.HasExited) {
                break
            }


            Start-Sleep `
                -Milliseconds 500
        }


        $process.Refresh()


        $stillRunning =
            -not $process.HasExited


        if ($stillRunning) {

            Stop-Process `
                -Id $process.Id `
                -Force `
                -ErrorAction SilentlyContinue


            $null =
                $process.WaitForExit(
                    5000
                )
        }


        $process.Refresh()


        if ($process.HasExited) {

            $exitCode =
                $process.ExitCode
        }
        else {

            $exitCode =
                $null
        }
    }
    finally {

        $env:PATH =
            $oldPath
    }


    # ========================================================
    # 8. CLASSIFY RESULT
    # ========================================================

    $stderrText =
        ""


    if (Test-Path $stderrLog) {

        $stderrText =
            Get-Content `
                $stderrLog `
                -Raw `
                -ErrorAction SilentlyContinue
    }


    $serialBytes =
        0


    if (Test-Path $serialLog) {

        $serialBytes =
            (
                Get-Item `
                    $serialLog
            ).Length
    }


    $classification =
        "NO_SERIAL_ACTIVITY"


    if ($serialBytes -gt 0) {

        $classification =
            "SERIAL_ACTIVITY_OBSERVED"
    }
    elseif (
        $stderrText -match
        'is an im4p'
    ) {

        $classification =
            "PAYLOAD_CONTAINER_REJECTED"
    }
    elseif (
        $stderrText -match
        'device tree firmware-version'
    ) {

        $classification =
            "DEVICE_TREE_NOT_PREPARED_FOR_QEMU_SPTM"
    }
    elseif (
        $stderrText -match
        'error opening'
    ) {

        $classification =
            "PAYLOAD_FILE_ADMISSION_FAILURE"
    }
    elseif ($stillRunning) {

        $classification =
            "PROCESS_ALIVE_NO_SERIAL_YET"
    }
    elseif (
        $null -ne $exitCode
    ) {

        $classification =
            "GUEST_EXITED_BEFORE_SERIAL"
    }


    $result =
        [ordered]@{

            phase =
                "05F"

            mode =
                $mode

            vphone_head =
                $vphoneSHA

            qemu_sptm =
                $qemuSHA

            run_seconds =
                $RunSeconds

            process_survived_window =
                $stillRunning

            exit_code =
                $exitCode

            serial_bytes =
                $serialBytes

            classification =
                $classification

            claims =
                [ordered]@{

                    payload_admission =
                        "PASS"

                    guest_execution_attempt =
                        "PASS"

                    serial_activity =
                        $(if ($serialBytes -gt 0) {
                            "OBSERVED"
                        }
                        else {
                            "NOT_OBSERVED"
                        })

                    deterministic_serial =
                        "NOT_TESTED"

                    apple_guest_boot =
                        "NOT_CLAIMED"

                    graphical_guest =
                        "NOT_TESTED"
                }
        }


    $result |
        ConvertTo-Json `
            -Depth 10 |
        Set-Content `
            -Path $resultPath `
            -Encoding UTF8


    Write-Host ""
    Write-Host `
        "============================================================" `
        -ForegroundColor Cyan

    Write-Host `
        " PHASE 5F FIRST RUNTIME PROBE RESULT" `
        -ForegroundColor Cyan

    Write-Host `
        "============================================================" `
        -ForegroundColor Cyan

    Write-Host ""

    Write-Host `
        "Payload admission : PASS" `
        -ForegroundColor Green

    Write-Host `
        "Execution attempt : PASS" `
        -ForegroundColor Green

    Write-Host `
        "Serial bytes      : $serialBytes" `
        -ForegroundColor Cyan

    Write-Host `
        "Classification    : $classification" `
        -ForegroundColor Cyan

    Write-Host ""

    if ($serialBytes -gt 0) {

        Write-Host `
            "SERIAL ACTIVITY     : OBSERVED" `
            -ForegroundColor Green

        Write-Host `
            "NEXT                : TWO-RUN DETERMINISTIC SERIAL VALIDATION" `
            -ForegroundColor Cyan
    }
    else {

        Write-Host `
            "SERIAL ACTIVITY     : NOT OBSERVED" `
            -ForegroundColor Yellow

        Write-Host `
            "NEXT                : REVIEW FIRST GUEST EXECUTION BOUNDARY" `
            -ForegroundColor Cyan
    }


    Write-Host ""

    Write-Host `
        "APPLE GUEST BOOT    : NOT CLAIMED" `
        -ForegroundColor Yellow

    Write-Host `
        "DETERMINISTIC SERIAL: NOT TESTED" `
        -ForegroundColor Yellow

    Write-Host `
        "GRAPHICAL GUEST     : NOT TESTED" `
        -ForegroundColor Yellow

    Write-Host ""

    Write-Host `
        "Serial log:" `
        -ForegroundColor Cyan

    Write-Host `
        "  $serialLog" `
        -ForegroundColor Cyan

    Write-Host `
        "stderr:" `
        -ForegroundColor Cyan

    Write-Host `
        "  $stderrLog" `
        -ForegroundColor Cyan

    Write-Host `
        "Result:" `
        -ForegroundColor Cyan

    Write-Host `
        "  $resultPath" `
        -ForegroundColor Cyan

    Write-Host ""


    $global:LASTEXITCODE = 0
}
catch {

    Write-Host ""
    Write-Host `
        "============================================================" `
        -ForegroundColor Red

    Write-Host `
        " PHASE 5F PROBE STOPPED - NO RUNTIME CLAIM" `
        -ForegroundColor Red

    Write-Host `
        "============================================================" `
        -ForegroundColor Red

    Write-Host ""

    Write-Host `
        $_.Exception.Message `
        -ForegroundColor Red

    Write-Host ""


    $global:LASTEXITCODE = 1
}