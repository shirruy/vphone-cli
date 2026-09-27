param(
    [string]$RepoRoot = "C:\Users\rbjos\source\vphone-cli-windows",

    [string]$QemuSourceDir =
        "C:\Users\rbjos\source\vphone-cli-windows\build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm",

    [string]$QemuExe =
        "C:\Users\rbjos\source\vphone-cli-windows\build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win\qemu-system-aarch64.exe",

    [string]$MingwBin =
        "C:\msys64\mingw64\bin"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$expectedBranch =
    "phase/05e-qemu-sptm-windows-feasibility"

$certifiedPhase5d =
    "a35190c76e1371b098cfcb403e536a98658becb9"

$expectedQemuBase =
    "2867d847d3471560e773120ee50c42dbcbb6d60b"

$patchPath =
    Join-Path `
        $RepoRoot `
        "windows\patches\qemu-sptm\phase05e-windows-portability.patch"

$validationDir =
    Join-Path `
        $RepoRoot `
        "build\phase05e-sealed-validation"

$stdoutPath =
    Join-Path `
        $validationDir `
        "stdout.log"

$stderrPath =
    Join-Path `
        $validationDir `
        "stderr.log"

$expectedMarker =
    "error opening XNU kernel"


function Get-Sha {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $sha = [string](
        git `
            -c core.longpaths=true `
            -c submodule.recurse=false `
            -C $Directory `
            rev-parse HEAD
    )

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to resolve Git HEAD: $Directory"
    }

    $sha =
        $sha.Trim().ToLowerInvariant()

    if ($sha -notmatch '^[0-9a-f]{40}$') {
        throw "Invalid Git SHA: [$sha]"
    }

    return $sha
}


function Normalize-Text {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return (
        $Value.
            Replace("`r`n", "`n").
            Replace("`r", "`n").
            TrimEnd()
    )
}


Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Cyan
Write-Host " PHASE 5E SEALED VALIDATION" `
    -ForegroundColor Cyan
Write-Host "============================================================" `
    -ForegroundColor Cyan
Write-Host ""


# ============================================================
# REPOSITORY LINEAGE
# ============================================================

Set-Location $RepoRoot

$branch = [string](
    git branch --show-current
)

if ($LASTEXITCODE -ne 0) {
    throw "Unable to resolve VPhone branch."
}

$branch =
    $branch.Trim()

if ($branch -ne $expectedBranch) {
    throw "Wrong Phase 5E branch: $branch"
}


$currentHead =
    Get-Sha `
        -Directory $RepoRoot


git merge-base `
    --is-ancestor `
    $certifiedPhase5d `
    $currentHead

if ($LASTEXITCODE -ne 0) {
    throw "Phase 5E does not descend from certified Phase 5D."
}


Write-Host "VPhone lineage : PASS" `
    -ForegroundColor Green


# ============================================================
# QEMU SOURCE BASE + PATCH
# ============================================================

$qemuSHA =
    Get-Sha `
        -Directory $QemuSourceDir

if ($qemuSHA -ne $expectedQemuBase) {
    throw "Wrong qemu-sptm base: $qemuSHA"
}


if (-not (Test-Path $patchPath)) {
    throw "Durable Phase 5E patch is missing."
}


$actualDiffLines = @(
    git `
        -c core.longpaths=true `
        -c submodule.recurse=false `
        -c core.autocrlf=false `
        -C $QemuSourceDir `
        diff `
        --ignore-submodules=all `
        --no-ext-diff `
        -- `
        "hw/arm/apple_dtree.c" `
        "hw/arm/apple_regs.c" `
        "hw/arm/darwin.c" `
        "hw/arm/xnuboot_sptm.c"
)


if ($LASTEXITCODE -ne 0) {
    throw "Unable to capture live qemu-sptm patch."
}


$actualDiff =
    Normalize-Text `
        -Value (
            $actualDiffLines -join
            [Environment]::NewLine
        )


$sealedDiff =
    Normalize-Text `
        -Value (
            Get-Content `
                -Path $patchPath `
                -Raw
        )


if ($actualDiff -ne $sealedDiff) {

    throw @"
Live qemu-sptm portability patch does not match the sealed patch.

Refusing Phase 5E validation.
"@
}


Write-Host "qemu-sptm base : PASS" `
    -ForegroundColor Green
Write-Host "Sealed patch   : EXACT MATCH" `
    -ForegroundColor Green


# ============================================================
# WINDOWS EXECUTABLE
# ============================================================

if (-not (Test-Path $QemuExe)) {
    throw "Native Windows qemu-system-aarch64.exe is missing."
}


$oldPath =
    $env:PATH

try {

    $env:PATH =
        "$MingwBin;$oldPath"


    $versionLines = @(
        & $QemuExe --version
    )

    if ($LASTEXITCODE -ne 0) {
        throw "QEMU --version failed."
    }


    $machineLines = @(
        & $QemuExe `
            -machine help
    )

    if ($LASTEXITCODE -ne 0) {
        throw "QEMU machine enumeration failed."
    }


    $machineText =
        $machineLines -join
        [Environment]::NewLine


    if (
        $machineText -notmatch
        '(?m)^\s*darwin(?:\s|$)'
    ) {
        throw "Darwin machine is not registered."
    }


    Write-Host "Windows EXE       : PASS" `
        -ForegroundColor Green
    Write-Host "Darwin registered : PASS" `
        -ForegroundColor Green


    # ========================================================
    # PAYLOAD-FREE RUNTIME PROBE
    # ========================================================

    if (Test-Path $validationDir) {

        Remove-Item `
            $validationDir `
            -Recurse `
            -Force
    }


    New-Item `
        -ItemType Directory `
        -Force `
        -Path $validationDir |
        Out-Null


    $arguments = @(
        "-machine", "darwin",
        "-accel", "tcg",
        "-display", "none",
        "-nodefaults",
        "-serial", "none",
        "-monitor", "none"
    )


    $process =
        Start-Process `
            -FilePath $QemuExe `
            -ArgumentList $arguments `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -PassThru


    if (-not $process.WaitForExit(10000)) {

        Stop-Process `
            -Id $process.Id `
            -Force `
            -ErrorAction SilentlyContinue

        throw "Darwin payload-free probe timed out."
    }


    $process.Refresh()

    $exitCode =
        $process.ExitCode


    if ($exitCode -eq 0) {
        throw "Payload-free Darwin probe unexpectedly returned zero."
    }


    $stdout = ""

    if (Test-Path $stdoutPath) {

        $stdout =
            Get-Content `
                $stdoutPath `
                -Raw `
                -ErrorAction SilentlyContinue
    }


    $stderr = ""

    if (Test-Path $stderrPath) {

        $stderr =
            Get-Content `
                $stderrPath `
                -Raw `
                -ErrorAction SilentlyContinue
    }


    $combined =
        @(
            $stdout,
            $stderr
        ) -join
        [Environment]::NewLine


    if (
        $combined -notmatch
        [regex]::Escape($expectedMarker)
    ) {

        throw @"
Darwin startup did not reach the expected XNU kernel boundary.

Expected:
$expectedMarker
"@
    }


    Write-Host "Machine init entered : PASS" `
        -ForegroundColor Green
    Write-Host "XNU boundary reached : PASS" `
        -ForegroundColor Green
    Write-Host "Fail closed          : PASS" `
        -ForegroundColor Green
}
finally {

    $env:PATH =
        $oldPath
}


Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Green
Write-Host " PHASE 5E SEALED VALIDATION PASS" `
    -ForegroundColor Green
Write-Host "============================================================" `
    -ForegroundColor Green
Write-Host ""

Write-Host "APPLE FIRMWARE       : NOT TESTED" `
    -ForegroundColor Yellow
Write-Host "APPLE KERNEL EXECUTION: NOT TESTED" `
    -ForegroundColor Yellow
Write-Host "APPLE GUEST BOOT     : NOT TESTED" `
    -ForegroundColor Yellow
Write-Host "SERIAL MILESTONE     : NOT TESTED" `
    -ForegroundColor Yellow

Write-Host ""

$global:LASTEXITCODE = 0