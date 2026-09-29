# Phase 5F guest integration / boot validation harness.
# Boots a ramdisk through the canonical QEMU/SPTM configuration and
# records ordered serial milestones, first-exception state, UART
# bytes, stderr, runtime duration, and natural-exit status.
#
# Usage:
#   run-guest-integration.ps1 -Ramdisk <path.dmg> -RunName <label> [-BootArgs "rd=md0 serial=3 -v ..."]
#
# Milestone comparison is ORDERED, not total-byte based.

param(
    [Parameter(Mandatory = $true)]
    [string]$Ramdisk,

    [Parameter(Mandatory = $true)]
    [string]$RunName,

    [int]$WindowSeconds = 30,

    [string]$BootArgs = 'rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = 'C:\Users\rbjos\source\vphone-cli-windows'
$QemuBuild = Join-Path $RepoRoot 'build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win'
$QemuExe = Join-Path $QemuBuild 'qemu-system-aarch64.exe'
$MingwBin = 'C:\msys64\mingw64\bin'
$PayloadRoot = Join-Path $env:USERPROFILE 'vphone-private\phase05f-known-good\payloads-v3'
$RunRoot = Join-Path $RepoRoot "build\phase05f-runtime\$RunName"

New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

# Clear any orphaned qemu from earlier failed harness runs so it
# cannot hold this run's serial file open.
Get-Process -Name 'qemu-system-aarch64' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

$serial = Join-Path $RunRoot 'uart0.log'
$so = Join-Path $RunRoot 'stdout.log'
$se = Join-Path $RunRoot 'stderr.log'
$result = Join-Path $RunRoot 'result.json'

function QPath([string]$p) {
    return ([System.IO.Path]::GetFullPath($p)).Replace('\', '/')
}

# Ordered milestone table (canonical baseline, index order matters).
$milestones = @(
    'iBoot version: qemu-sptm',
    'Darwin Image4 Extension Version',
    'AMFI: Booted in a VM',
    'AppleARMBacklight::start',
    'AppleCredentialManager: init',
    'handle_mount:',
    'Darwin Ignition Sequence Version',
    'hello from launchd.1',
    'ignition sequence complete'
)

# Fatal-exception markers (any hit = exception present).
$exceptionMarkers = @(
    'panic',
    'Kernel trap',
    'data abort',
    'prefetch abort',
    'ESR',
    'fatal exception'
)

$argsList = @(
    '-M', 'darwin',
    '-bootkc', (QPath (Join-Path $PayloadRoot 'bootkc.bin')),
    '-dtree', (QPath (Join-Path $PayloadRoot 'dtree.bin')),
    '-tc', (QPath (Join-Path $PayloadRoot 'trustcache.bin')),
    '-ramdisk', (QPath $Ramdisk),
    '-args', ('"' + $BootArgs + '"'),
    '-display', 'none',
    '-monitor', 'none',
    '-chardev', ('file,id=uart0,path=' + (QPath $serial)),
    '-serial', 'chardev:uart0',
    '-m', '8G',
    '-sptm', (QPath (Join-Path $PayloadRoot 'sptm.bin')),
    '-txm', (QPath (Join-Path $PayloadRoot 'txm.bin'))
)

# Start-Process joins array elements with spaces; quote any element
# containing spaces so qemu receives the boot-args as one argument.
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

Write-Host ("QEMU PID {0}" -f $proc.Id)

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$serialBytes = 0
$procExited = $false
$maxIterations = [int][math]::Ceiling($WindowSeconds / 2.0)
$iteration = 0
while ($iteration -lt $maxIterations) {
    $iteration++
    Start-Sleep -Seconds 2
    $proc.Refresh()
    if (Test-Path $serial) { $serialBytes = (Get-Item $serial).Length }
    if ($proc.HasExited) { $procExited = $true; break }
}
$sw.Stop()

$elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)

$proc.Refresh()
$naturalExit = $procExited
$exitCode = $null
if ($procExited) {
    $exitCode = $proc.ExitCode
} else {
    # taskkill kills the full tree and is reliable for this child
    # process; Stop-Process -Force is the fallback.
    & taskkill /F /T /PID $proc.Id 2>$null | Out-Null
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    try {
        [void]$proc.WaitForExit(10000)
    } catch {}
    $proc.Refresh()
    $exitCode = $proc.ExitCode
}

if (Test-Path $serial) {
    $serialBytes = (Get-Item $serial).Length
}

# Analyze UART.
$uartText = ''
$uartSha = $null
$foundMilestones = @()
$firstException = $null

if ($serialBytes -gt 0) {
    # qemu may still hold the serial file briefly after being
    # killed; retry the open with a bounded wait.
    $b = $null
    for ($retry = 0; $retry -lt 20 -and $null -eq $b; $retry++) {
        try {
            $b = [IO.File]::ReadAllBytes($serial)
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if ($null -eq $b) {
        throw "serial log unreadable after kill: $serial"
    }
    $uartText = [Text.Encoding]::ASCII.GetString($b)
    $uartSha = (Get-FileHash $serial -Algorithm SHA256).Hash.ToLowerInvariant()

    foreach ($m in $milestones) {
        $foundMilestones += [ordered]@{
            milestone = $m
            found = $uartText.Contains($m)
            index = $uartText.IndexOf($m)
        }
    }

    foreach ($em in $exceptionMarkers) {
        $i = $uartText.IndexOf($em, [System.StringComparison]::OrdinalIgnoreCase)
        if ($i -ge 0) {
            $ctx = $uartText.Substring(
                [Math]::Max(0, $i - 120),
                [Math]::Min(240, $uartText.Length - [Math]::Max(0, $i - 120)))
            $firstException = [ordered]@{
                marker = $em
                index = $i
                context = $ctx
            }
            break
        }
    }
}

$stderrText = ''
if (Test-Path $se) {
    $stderrText = (Get-Content $se -Raw -ErrorAction SilentlyContinue)
    if ($null -eq $stderrText) { $stderrText = '' }
}

$record = [ordered]@{
    run_name = $RunName
    stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    ramdisk_sha256 = (Get-FileHash $Ramdisk -Algorithm SHA256).Hash.ToLowerInvariant()
    qemu_sha256 = (Get-FileHash $QemuExe -Algorithm SHA256).Hash.ToLowerInvariant()
    boot_args = $BootArgs
    serial_bytes = $serialBytes
    serial_sha256 = $uartSha
    elapsed_seconds = $elapsed
    natural_exit = $naturalExit
    exit_code = $exitCode
    milestones = $foundMilestones
    first_exception = $firstException
    stderr_bytes = [math]::Max(0, $stderrText.Length)
    stderr = $stderrText
}

$record | ConvertTo-Json -Depth 6 |
    Set-Content $result -Encoding UTF8

Write-Host ("RESULT: serial_bytes={0} natural_exit={1} exit={2}" -f
    $serialBytes, $naturalExit, $exitCode)
Write-Host '=== MILESTONES ==='
foreach ($m in $foundMilestones) {
    $tag = if ($m.found) { 'PASS' } else { 'MISS' }
    Write-Host ("  {0,-5} idx={1,-6} {2}" -f $tag, $m.index, $m.milestone)
}
if ($null -ne $firstException) {
    Write-Host ("FIRST_EXCEPTION: marker={0} index={1}" -f
        $firstException.marker, $firstException.index)
} else {
    Write-Host 'FIRST_EXCEPTION: NONE'
}
Write-Host "EVIDENCE: $RunRoot"
