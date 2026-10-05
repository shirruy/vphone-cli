# 57ZZ runtime boundary: decisive breakpoint run orchestrator.
# DIAGNOSTIC ONLY - no production QEMU behavior change.
#
# Boots the known-good Phase05F fixture with QEMU gdbstub, lets the kernel
# reach a steady state (warmup), attaches gdb-multiarch with the capture
# script, and collects raw breakpoint evidence for the AppleA7IOP start
# candidates and AppleA7IOPNub::withRegistryEntry.
#
# Usage:
#   phase05f-57zz-runtime-breakpoint-run.ps1 -RunName <label> -Dtree <path> [-GdbPort] [-WarmupSeconds] [-WindowSeconds]

param(
    [Parameter(Mandatory = $true)]
    [string]$RunName,

    [Parameter(Mandatory = $true)]
    [string]$Dtree,

    [int]$GdbPort = 1235,

    [int]$MonitorPort = 4444,

    [int]$WarmupSeconds = 18,

    [int]$WindowSeconds = 150,

    [int]$KillQemuAfter = 220
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = 'C:\Users\rbjos\source\vphone-cli-windows'
$QemuBuild = Join-Path $RepoRoot 'build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win'
$QemuExe = Join-Path $QemuBuild 'qemu-system-aarch64.exe'
$MingwBin = 'C:\msys64\mingw64\bin'
$GdbExe = Join-Path $MingwBin 'gdb-multiarch.exe'
$PayloadRoot = Join-Path $env:USERPROFILE 'vphone-private\phase05f-known-good\payloads-v3'
$RunRoot = Join-Path $RepoRoot "build\phase05f-runtime\$RunName"
$CaptureScript = 'C:\Users\rbjos\source\vphone-cli-windows\scripts\phase05f-57zz-runtime-gdb-capture-v11.py'

New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

Get-Process -Name 'qemu-system-aarch64' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

$serial = Join-Path $RunRoot 'uart0.log'
$so = Join-Path $RunRoot 'stdout.log'
$se = Join-Path $RunRoot 'stderr.log'
$result = Join-Path $RunRoot 'result.json'
$gdbLog = Join-Path $RunRoot 'gdb-session.log'
$gdbCapture = Join-Path $RunRoot 'gdb-capture.json'

function QPath([string]$p) {
    return ([System.IO.Path]::GetFullPath($p)).Replace('\', '/')
}

$BootArgs = 'rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort'

# Boot WITHOUT -S: kernel runs immediately; we attach after warmup so page
# tables are live and the slide can be derived from live memory.
$argsList = @(
    '-M', 'darwin',
    '-bootkc', (QPath (Join-Path $PayloadRoot 'bootkc.bin')),
    '-dtree', (QPath $Dtree),
    '-tc', (QPath (Join-Path $PayloadRoot 'trustcache.bin')),
    '-ramdisk', (QPath (Join-Path $PayloadRoot 'ramdisk.dmg')),
    '-args', ('"' + $BootArgs + '"'),
    '-display', 'none',
    '-monitor', 'none',
    '-chardev', ('file,id=uart0,path=' + (QPath $serial)),
    '-serial', 'chardev:uart0',
    '-m', '8G',
    '-sptm', (QPath (Join-Path $PayloadRoot 'sptm.bin')),
    '-txm', (QPath (Join-Path $PayloadRoot 'txm.bin')),
    '-gdb', ('tcp:127.0.0.1:' + $GdbPort),
    '-monitor', ('tcp:127.0.0.1:' + $MonitorPort + ',server,nowait')
)

$argString = ($argsList | ForEach-Object {
    if ($_ -match '\s' -and -not $_.StartsWith('"')) {
        '"' + $_ + '"'
    } else {
        $_
    }
}) -join ' '

$oldPath = $env:PATH
try {
    $env:PATH = "$MingwBin;$oldPath"
    $proc = Start-Process `
        -FilePath $QemuExe `
        -WorkingDirectory $QemuBuild `
        -ArgumentList $argString `
        -RedirectStandardOutput $so `
        -RedirectStandardError $se `
        -PassThru `
        -WindowStyle Hidden
} finally {
    $env:PATH = $oldPath
}

if ($null -eq $proc) { throw 'qemu start failed' }
Write-Host ("QEMU PID {0} gdb tcp:127.0.0.1:{1}" -f $proc.Id, $GdbPort)

# Warmup: let the kernel boot past MMU-on so kernel virtual memory is live.
Write-Host ("Warmup {0}s (kernel boots to steady state before GDB attach)..." -f $WarmupSeconds)
$deadline = (Get-Date).AddSeconds($WarmupSeconds)
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    Start-Sleep -Milliseconds 500
}

if ($proc.HasExited) {
    throw "qemu exited during warmup: exit=$($proc.ExitCode)"
}

# Run GDB capture
$env:P2_OUT_DIR = $RunRoot
$env:P2_GDB_PORT = "$GdbPort"
$env:PHASE05F_BOOTKC = (Join-Path $PayloadRoot 'bootkc.bin')
$gdbCmds = Join-Path $RunRoot 'gdb.cmds'
$targetLine = "target remote 127.0.0.1:$GdbPort"
$sourceLine = "source $($CaptureScript.Replace('\', '/'))"
$cmdLines = @(
    'set pagination off',
    'set confirm off',
    'set height 0',
    'set width 0',
    $targetLine,
    $sourceLine
)
[System.IO.File]::WriteAllLines($gdbCmds, [string[]]$cmdLines, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ("Attaching GDB (window {0}s)..." -f $WindowSeconds)
$gdbStart = Get-Date
$gdbCmd = "`"$GdbExe`" --batch -x `"$gdbCmds`" 2>&1"
$gdbOutput = & cmd.exe /c $gdbCmd
$gdbExit = $LASTEXITCODE
$gdbOutput | Set-Content -LiteralPath $gdbLog -Encoding UTF8
$gdbElapsed = [math]::Round(((Get-Date) - $gdbStart).TotalSeconds, 2)
Write-Host ("GDB finished exit={0} elapsed={1}s" -f $gdbExit, $gdbElapsed)

# Give a moment for file flush, then stop QEMU
Start-Sleep -Seconds 2
if (-not $proc.HasExited) {
    & taskkill /F /T /PID $proc.Id 2>$null | Out-Null
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    try { [void]$proc.WaitForExit(10000) } catch {}
}
$proc.Refresh()

$serialBytes = 0
if (Test-Path $serial) { $serialBytes = (Get-Item $serial).Length }

$record = [ordered]@{
    run_name = $RunName
    stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    dtree_sha256 = (Get-FileHash $Dtree -Algorithm SHA256).Hash.ToLowerInvariant()
    bootkc_sha256 = (Get-FileHash (Join-Path $PayloadRoot 'bootkc.bin') -Algorithm SHA256).Hash.ToLowerInvariant()
    qemu_sha256 = (Get-FileHash $QemuExe -Algorithm SHA256).Hash.ToLowerInvariant()
    gdb_sha256 = (Get-FileHash $GdbExe -Algorithm SHA256).Hash.ToLowerInvariant()
    warmup_seconds = $WarmupSeconds
    gdb_window_seconds = $WindowSeconds
    gdb_exit_code = $gdbExit
    gdb_elapsed_seconds = $gdbElapsed
    serial_bytes = $serialBytes
    serial_sha256 = $(if ($serialBytes -gt 0) { (Get-FileHash $serial -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null })
    natural_exit = $false  # harness always kills QEMU after the capture window
    stderr_bytes = $(if (Test-Path $se) { (Get-Item $se).Length } else { 0 })
}

if (Test-Path $gdbCapture) {
    $record.capture_json = (Get-Item $gdbCapture).Name
}

$record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $result -Encoding UTF8

Write-Host ("RESULT: serial_bytes={0} gdb_exit={1}" -f $serialBytes, $gdbExit)
if (Test-Path $gdbCapture) {
    Write-Host "CAPTURE: $gdbCapture"
    $cap = Get-Content $gdbCapture -Raw | ConvertFrom-Json
    Write-Host ("CLASSIFICATION: {0}" -f $cap.classification)
    Write-Host ("SLIDE: {0}" -f ($cap.slide | ConvertTo-Json -Compress))
    Write-Host ("EVENTS: {0}" -f $cap.events.Count)
} else {
    Write-Host "CAPTURE: MISSING"
}
Write-Host "EVIDENCE: $RunRoot"





