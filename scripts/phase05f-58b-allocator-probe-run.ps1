# Phase 05F 58B: allocator probe orchestrator.
# Boots QEMU with ascwrap DT, attaches GDB, runs probe58b (allocator
# hit capture), writes allocator-name-probe.json.

param(
    [Parameter(Mandatory = $true)]
    [string]$RunName,

    [int]$GdbPort = 1235,
    [int]$WarmupSeconds = 0,
    [int]$WindowSeconds = 90,

    [switch]$KeepQemu
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$QemuBuild = Join-Path $RepoRoot 'build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win'
$QemuExe = Join-Path $QemuBuild 'qemu-system-aarch64.exe'
$MingwBin = 'C:\msys64\mingw64\bin'
$GdbExe = Join-Path $MingwBin 'gdb-multiarch.exe'
$PayloadRoot = Join-Path $env:USERPROFILE 'vphone-private\phase05f-known-good\payloads-v3'
$Dtree = Join-Path $RepoRoot 'build\phase05f-runtime\dt-fixtures\dtree_ascwrap.bin'
$ProbeScript = Join-Path $RepoRoot 'scripts\phase05f-58b-allocator-name-probe.py'
$RunRoot = Join-Path $RepoRoot "build\phase05f-runtime\$RunName"
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

Get-Process -Name 'qemu-system-aarch64' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

$serial = Join-Path $RunRoot 'uart0.log'
$so = Join-Path $RunRoot 'stdout.log'
$se = Join-Path $RunRoot 'stderr.log'

function QPath([string]$p) {
    return ([System.IO.Path]::GetFullPath($p)).Replace('\', '/')
}

$BootArgs = 'rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort'
$argsList = @(
    '-M', 'darwin',
    '-bootkc', (QPath (Join-Path $PayloadRoot 'bootkc.bin')),
    '-dtree', (QPath $Dtree),
    '-tc', (QPath (Join-Path $PayloadRoot 'trustcache.bin')),
    '-ramdisk', (QPath (Join-Path $PayloadRoot 'ramdisk.dmg')),
    '-args', $BootArgs,
    '-display', 'none',
    '-monitor', 'none',
    '-chardev', ("file,id=uart0,path=" + (QPath $serial)),
    '-serial', 'chardev:uart0',
    '-m', '8G',
    '-sptm', (QPath (Join-Path $PayloadRoot 'sptm.bin')),
    '-txm', (QPath (Join-Path $PayloadRoot 'txm.bin')),
    '-gdb', "tcp:127.0.0.1:$GdbPort",
    '-S'
)
$argString = ($argsList | ForEach-Object {
    if ($_ -match '\s' -and -not $_.StartsWith('"')) { '"' + $_ + '"' } else { $_ }
}) -join ' '

$oldPath = $env:PATH
try {
    $env:PATH = "$MingwBin;$oldPath"
    $proc = Start-Process -FilePath $QemuExe -WorkingDirectory $QemuBuild `
        -ArgumentList $argString -RedirectStandardOutput $so -RedirectStandardError $se `
        -PassThru -WindowStyle Hidden
} finally { $env:PATH = $oldPath }

Write-Host ("QEMU PID {0}" -f $proc.Id)
$deadline = (Get-Date).AddSeconds($WarmupSeconds)
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    Start-Sleep -Milliseconds 500
}
if ($proc.HasExited) { throw "qemu exited during warmup: exit=$($proc.ExitCode)" }

# GDB commands: source probe then invoke
$gdbCmds = Join-Path $RunRoot 'gdb.cmds'
$cmdLines = @(
    'set pagination off',
    'set confirm off',
    'set height 0',
    'set width 0',
    "target remote 127.0.0.1:$GdbPort",
    "source $($ProbeScript.Replace('\', '/'))",
    'probe58b'
)
[System.IO.File]::WriteAllLines($gdbCmds, [string[]]$cmdLines, (New-Object System.Text.UTF8Encoding($false)))

$env:P2_OUT_DIR = $RunRoot
$env:P2_GDB_PORT = "$GdbPort"
$env:PHASE05F_BOOTKC = (Join-Path $PayloadRoot 'bootkc.bin')

$gdbLog = Join-Path $RunRoot 'gdb-session.log'
Write-Host "Attaching GDB + probe58b..."
$gdbCmd = "`"$GdbExe`" --batch -x `"$gdbCmds`" 2>&1"
$gdbOutput = & cmd.exe /c $gdbCmd
$gdbExit = $LASTEXITCODE
$gdbOutput | Set-Content -LiteralPath $gdbLog -Encoding UTF8
Write-Host ("GDB exit={0}" -f $gdbExit)

if ($KeepQemu) {
    Write-Host ("QEMU still running (PID {0}) for walk pass" -f $proc.Id)
} else {
    Start-Sleep -Seconds 2
    if (-not $proc.HasExited) {
        & taskkill /F /T /PID $proc.Id 2>$null | Out-Null
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        try { [void]$proc.WaitForExit(10000) } catch {}
    }
}

$probeJson = Join-Path $RunRoot 'allocator-name-probe.json'
if (Test-Path $probeJson) {
    Write-Host "PROBE OUTPUT: $probeJson"
    Get-Content $probeJson | Select-Object -First 30
} else {
    Write-Host "NO PROBE OUTPUT; check gdb-session.log"
    Get-Content $gdbLog | Select-Object -Last 30
}
