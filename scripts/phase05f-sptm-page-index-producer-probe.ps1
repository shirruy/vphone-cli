#Requires -Version 7.0
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ============================================================
# PHASE 5F - SPTM PAGE-INDEX PRODUCER PROBE
#
# Diagnostic only.
# Creates private SPTM copies with BRK at:
#   runtime 0xfffffff0070d5700  before: sub x8,x22,x8
#   runtime 0xfffffff0070d570c  before: str w8,[x9,#0xfc8]
#
# Goal:
#   capture the exact x8/x22 values that create the stored
#   page index later consumed at 0xfffffff0070d57fc.
#
# Original SPTM is never modified.
# ============================================================

$RepoRoot = "C:\Users\rbjos\source\vphone-cli-windows"
$ExpectedBranch = "phase/05f-minimum-guest-payload-serial"

$QemuBuild = Join-Path $RepoRoot "build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win"
$QemuExe = Join-Path $QemuBuild "qemu-system-aarch64.exe"
$MingwBin = "C:\msys64\mingw64\bin"

$PayloadRoot = Join-Path $env:USERPROFILE "vphone-private\phase05f-known-good\payloads-v3"
$BootKC = Join-Path $PayloadRoot "bootkc.bin"
$DeviceTree = Join-Path $PayloadRoot "dtree.bin"
$TrustCache = Join-Path $PayloadRoot "trustcache.bin"
$Ramdisk = Join-Path $PayloadRoot "ramdisk.dmg"
$SptmOriginal = Join-Path $PayloadRoot "sptm.bin"
$Txm = Join-Path $PayloadRoot "txm.bin"

$BootArgs = "rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort"

$RuntimeSlide = [UInt64]::Parse("0000000020000000", [Globalization.NumberStyles]::HexNumber)

$RuntimeBeforeSub = [UInt64]::Parse("fffffff0070d5700", [Globalization.NumberStyles]::HexNumber)
$RuntimeBeforeStore = [UInt64]::Parse("fffffff0070d570c", [Globalization.NumberStyles]::HexNumber)

$StaticBeforeSub = [UInt64]($RuntimeBeforeSub + $RuntimeSlide)
$StaticBeforeStore = [UInt64]($RuntimeBeforeStore + $RuntimeSlide)

$ExpectedSubBytes = [byte[]]@(0xC8,0x02,0x08,0xCB)
$ExpectedStoreBytes = [byte[]]@(0x28,0xC9,0x0F,0xB9)
$BrkBytes = [byte[]]@(0x00,0x00,0x20,0xD4) # brk #0

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$WorkRoot = Join-Path $RepoRoot "build\phase05f-runtime\sptm-page-index-producer\$Stamp"
$ExperimentRoot = Join-Path $env:USERPROFILE "vphone-private\phase05f-known-good\experiments"

New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
New-Item -ItemType Directory -Force -Path $ExperimentRoot | Out-Null

function Require-File {
    param([string]$Name, [string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing $Name : $Path"
    }

    $item = Get-Item -LiteralPath $Path

    if ($item.Length -le 0) {
        throw "Empty $Name : $Path"
    }

    Write-Host ("{0,-18}: PASS ({1} bytes)" -f $Name, $item.Length) -ForegroundColor Green
}

function QPath {
    param([string]$Path)
    return ([System.IO.Path]::GetFullPath($Path)).Replace("\", "/")
}

function HexBytes {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString("X2") }) -join " ")
}

function Map-StaticVA-ToFileOffset {
    param(
        [string]$MachOPath,
        [UInt64]$StaticVA
    )

    $stream = [System.IO.File]::OpenRead($MachOPath)
    $reader = [System.IO.BinaryReader]::new($stream)

    try {
        $magic = $reader.ReadUInt32()

        if ($magic -ne [Convert]::ToUInt32("FEEDFACF", 16)) {
            throw ("Unexpected Mach-O magic: 0x{0:x8}" -f $magic)
        }

        $stream.Position = 16
        $ncmds = $reader.ReadUInt32()
        $stream.Position = 32

        for ($i = 0; $i -lt $ncmds; $i++) {
            $commandStart = $stream.Position
            $cmd = $reader.ReadUInt32()
            $cmdsize = $reader.ReadUInt32()

            if ($cmdsize -lt 8) {
                throw "Invalid Mach-O load command size."
            }

            if ($cmd -eq 0x19) {
                $nameBytes = $reader.ReadBytes(16)
                $name = ([Text.Encoding]::ASCII.GetString($nameBytes)).Trim([char]0)

                $vmaddr = $reader.ReadUInt64()
                $vmsize = $reader.ReadUInt64()
                $fileoff = $reader.ReadUInt64()
                $filesize = $reader.ReadUInt64()

                if ($StaticVA -ge $vmaddr -and $StaticVA -lt ($vmaddr + $vmsize)) {
                    $within = $StaticVA - $vmaddr

                    if ($within -ge $filesize) {
                        throw "Static VA is not backed by file bytes."
                    }

                    return [pscustomobject]@{
                        Segment = $name
                        Offset = [UInt64]($fileoff + $within)
                    }
                }
            }

            $stream.Position = $commandStart + $cmdsize
        }
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }

    throw ("Unable to map VA 0x{0:x16}" -f $StaticVA)
}

function Make-BrkCopy {
    param(
        [string]$Name,
        [UInt64]$StaticVA,
        [byte[]]$ExpectedBytes
    )

    $mapped = Map-StaticVA-ToFileOffset -MachOPath $SptmOriginal -StaticVA $StaticVA
    $bytes = [System.IO.File]::ReadAllBytes($SptmOriginal)

    $actual = [byte[]]::new(4)
    [Array]::Copy($bytes, [int]$mapped.Offset, $actual, 0, 4)

    for ($i = 0; $i -lt 4; $i++) {
        if ($actual[$i] -ne $ExpectedBytes[$i]) {
            throw (
                "$Name original bytes mismatch. Expected [" +
                (HexBytes $ExpectedBytes) +
                "] got [" +
                (HexBytes $actual) +
                "]"
            )
        }
    }

    $copy = Join-Path $ExperimentRoot ("sptm." + $Name + ".brk.bin")
    $patched = [byte[]]::new($bytes.Length)
    [Array]::Copy($bytes, $patched, $bytes.Length)
    [Array]::Copy($BrkBytes, 0, $patched, [int]$mapped.Offset, 4)
    [System.IO.File]::WriteAllBytes($copy, $patched)

    return [pscustomobject]@{
        Name = $Name
        Path = $copy
        Segment = $mapped.Segment
        FileOffset = $mapped.Offset
        StaticVA = $StaticVA
    }
}

function Parse-LastCPUBlockBeforeFirstException {
    param([string]$DebugPath)

    $lines = @(Get-Content -LiteralPath $DebugPath -ErrorAction Stop)
    $exceptionIndex = -1

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^Taking exception') {
            $exceptionIndex = $i
            break
        }
    }

    if ($exceptionIndex -lt 0) {
        throw "No exception found in debug log."
    }

    $pcIndex = -1

    for ($i = $exceptionIndex - 1; $i -ge 0; $i--) {
        if ($lines[$i] -match '^\s*PC=[0-9a-fA-F]{16}\s+X00=') {
            $pcIndex = $i
            break
        }
    }

    if ($pcIndex -lt 0) {
        throw "No CPU block found before first exception."
    }

    $end = [Math]::Min($exceptionIndex - 1, $pcIndex + 12)
    $block = @($lines[$pcIndex..$end])
    $text = $block -join [Environment]::NewLine

    function Grab([string]$Reg) {
        if ($text -match ("(?im)\b" + [regex]::Escape($Reg) + "=([0-9a-fA-F]{16})")) {
            return [Convert]::ToUInt64($Matches[1], 16)
        }
        return $null
    }

    return [pscustomobject]@{
        Text = $text
        PC = Grab "PC"
        X08 = Grab "X08"
        X09 = Grab "X09"
        X20 = Grab "X20"
        X22 = Grab "X22"
    }
}

function Run-Probe {
    param(
        [Parameter(Mandatory = $true)]$Probe,
        [Parameter(Mandatory = $true)][string]$ExpectedRuntimePC
    )

    $runRoot = Join-Path $WorkRoot $Probe.Name
    New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

    $debugPath = Join-Path $runRoot "cpu-int.log"
    $serialPath = Join-Path $runRoot "uart0.log"
    $stdoutPath = Join-Path $runRoot "stdout.log"
    $stderrPath = Join-Path $runRoot "stderr.log"

    Get-Process qemu-system-aarch64 -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    Start-Sleep -Milliseconds 300

    $args = @(
        "-M", "darwin",
        "-bootkc", (QPath $BootKC),
        "-dtree", (QPath $DeviceTree),
        "-tc", (QPath $TrustCache),
        "-ramdisk", (QPath $Ramdisk),
        "-args", $BootArgs,
        "-display", "none",
        "-monitor", "none",
        "-chardev", ("file,id=uart0,path=" + (QPath $serialPath)),
        "-serial", "chardev:uart0",
        "-m", "8G",
        "-sptm", (QPath $Probe.Path),
        "-txm", (QPath $Txm),
        "-d", "cpu,int",
        "-D", (QPath $debugPath)
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $QemuExe
    $psi.WorkingDirectory = $QemuBuild
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.Environment["PATH"] = "$MingwBin;$env:PATH"

    foreach ($arg in $args) {
        [void]$psi.ArgumentList.Add([string]$arg)
    }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi

    if (-not $proc.Start()) {
        throw "Unable to start $($Probe.Name) probe."
    }

    Write-Host "QEMU PID           : $($proc.Id)" -ForegroundColor Green

    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $deadline = (Get-Date).AddSeconds(8)
    $exceptionSeen = $false

    while ((Get-Date) -lt $deadline) {
        $proc.Refresh()

        if ($proc.HasExited) {
            break
        }

        if (Test-Path -LiteralPath $debugPath) {
            try {
                $tail = @(Get-Content -LiteralPath $debugPath -Tail 20 -ErrorAction SilentlyContinue)

                if ($tail -match '^Taking exception') {
                    $exceptionSeen = $true
                    break
                }
            }
            catch {}
        }

        Start-Sleep -Milliseconds 30
    }

    $proc.Refresh()

    if (-not $proc.HasExited) {
        try {
            $proc.Kill($true)
        }
        catch {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }

        [void]$proc.WaitForExit(10000)
    }

    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()

    Set-Content -LiteralPath $stdoutPath -Value $stdout -Encoding utf8NoBOM
    Set-Content -LiteralPath $stderrPath -Value $stderr -Encoding utf8NoBOM

    if (-not $exceptionSeen) {
        throw "$($Probe.Name) did not reach the diagnostic BRK within 8 seconds."
    }

    $state = Parse-LastCPUBlockBeforeFirstException -DebugPath $debugPath
    $actualPC = ("{0:x16}" -f $state.PC)

    if ($actualPC -ne $ExpectedRuntimePC.ToLowerInvariant()) {
        throw "Unexpected pre-exception PC for $($Probe.Name): 0x$actualPC"
    }

    return [pscustomobject]@{
        RunRoot = $runRoot
        DebugPath = $debugPath
        State = $state
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PHASE 5F - SPTM PAGE-INDEX PRODUCER PROBE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $RepoRoot

$branch = ([string](git branch --show-current)).Trim()

if ($branch -ne $ExpectedBranch) {
    throw "Wrong branch. Expected [$ExpectedBranch], got [$branch]."
}

Write-Host "Branch            : $branch" -ForegroundColor Green

Require-File "qemu.exe" $QemuExe
Require-File "bootkc" $BootKC
Require-File "dtree" $DeviceTree
Require-File "trustcache" $TrustCache
Require-File "ramdisk" $Ramdisk
Require-File "sptm original" $SptmOriginal
Require-File "txm" $Txm

Write-Host ""
Write-Host "[1/4] Creating exact private BRK probes..." -ForegroundColor Yellow

$Probe5700 = Make-BrkCopy `
    -Name "before-sub-0d5700" `
    -StaticVA $StaticBeforeSub `
    -ExpectedBytes $ExpectedSubBytes

$Probe570C = Make-BrkCopy `
    -Name "before-store-0d570c" `
    -StaticVA $StaticBeforeStore `
    -ExpectedBytes $ExpectedStoreBytes

Write-Host ("0d5700 file offset : 0x{0:x}" -f $Probe5700.FileOffset) -ForegroundColor Green
Write-Host ("0d570c file offset : 0x{0:x}" -f $Probe570C.FileOffset) -ForegroundColor Green
Write-Host "Original SPTM       : PRESERVED" -ForegroundColor Green

Write-Host ""
Write-Host "[2/4] Capturing registers BEFORE sub x8,x22,x8..." -ForegroundColor Yellow

$Run5700 = Run-Probe `
    -Probe $Probe5700 `
    -ExpectedRuntimePC "fffffff0070d5700"

Write-Host $Run5700.State.Text
Write-Host ""

Write-Host "[3/4] Capturing registers BEFORE str w8,[x9,#0xfc8]..." -ForegroundColor Yellow

$Run570C = Run-Probe `
    -Probe $Probe570C `
    -ExpectedRuntimePC "fffffff0070d570c"

Write-Host $Run570C.State.Text
Write-Host ""

Write-Host "[4/4] Reconciling producer arithmetic..." -ForegroundColor Yellow

$x8Before = [UInt64]$Run5700.State.X08
$x22Before = [UInt64]$Run5700.State.X22
$x8BeforeStore = [UInt64]$Run570C.State.X08

$diff = [UInt64](($x22Before - $x8Before) -band [UInt64]::MaxValue)
$pages64 = $diff -shr 14
$storedW8 = [UInt32]($pages64 -band 0xffffffff)

$classification = "PRODUCER_ARITHMETIC_CAPTURED"

if (
    $x8Before -eq [UInt64]0x0000010000000000 -and
    $x22Before -eq [UInt64]0x0000000015ea0000 -and
    $storedW8 -eq [UInt32]0xfc0057a8
) {
    $classification = "DRAM_BASE_SUBTRACTION_UNDERFLOW_CONFIRMED"
}
elseif ($storedW8 -eq [UInt32]0xfc0057a8) {
    $classification = "PAGE_INDEX_WRAP_CONFIRMED"
}

Write-Host ("x8 before sub      : 0x{0:x16}" -f $x8Before) -ForegroundColor Cyan
Write-Host ("x22 before sub     : 0x{0:x16}" -f $x22Before) -ForegroundColor Cyan
Write-Host ("64-bit difference  : 0x{0:x16}" -f $diff) -ForegroundColor Cyan
Write-Host ("difference >> 14   : 0x{0:x16}" -f $pages64) -ForegroundColor Cyan
Write-Host ("stored low w8      : 0x{0:x8}" -f $storedW8) -ForegroundColor Cyan
Write-Host ("x8 before store    : 0x{0:x16}" -f $x8BeforeStore) -ForegroundColor Cyan
Write-Host "Classification     : $classification" -ForegroundColor Green

$result = [ordered]@{
    phase = "05F"
    gate = "sptm-page-index-producer-probe"
    original_sptm_preserved = $true

    before_sub = [ordered]@{
        runtime_pc = "0xfffffff0070d5700"
        x8 = ("0x{0:x16}" -f $x8Before)
        x22 = ("0x{0:x16}" -f $x22Before)
        trace = $Run5700.State.Text
    }

    before_store = [ordered]@{
        runtime_pc = "0xfffffff0070d570c"
        x8 = ("0x{0:x16}" -f $x8BeforeStore)
        x9 = ("0x{0:x16}" -f [UInt64]$Run570C.State.X09)
        trace = $Run570C.State.Text
    }

    arithmetic = [ordered]@{
        difference = ("0x{0:x16}" -f $diff)
        pages64 = ("0x{0:x16}" -f $pages64)
        stored_w8 = ("0x{0:x8}" -f $storedW8)
    }

    classification = $classification
    apple_guest_boot = "NOT_CLAIMED"
}

$resultPath = Join-Path $WorkRoot "result.json"

$result |
    ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $resultPath -Encoding utf8NoBOM

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PAGE-INDEX PRODUCER PROBE COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Evidence:" -ForegroundColor Cyan
Write-Host $resultPath -ForegroundColor Cyan
Write-Host $Run5700.DebugPath -ForegroundColor Cyan
Write-Host $Run570C.DebugPath -ForegroundColor Cyan
Write-Host ""
Write-Host "APPLE GUEST BOOT : NOT CLAIMED" -ForegroundColor Yellow
Write-Host ""


