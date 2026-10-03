# 57ZZ Part 15B: control vs ANS-enabled differential boot.
#
# Usage:
#   phase05f-57zz-part15b-ans-runtime-boot.ps1 -RunName <label> -Dtree <path> [-WindowSeconds 45]
#
# Everything else (bootkc, trustcache, ramdisk, sptm, txm, args, qemu)
# is identical across runs.

param(
    [Parameter(Mandatory = $true)]
    [string]$RunName,

    [Parameter(Mandatory = $true)]
    [string]$Dtree,

    [int]$WindowSeconds = 45,

    [string]$ExtraQemuArgs = ''
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

$BootArgs = 'rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort'

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
    '-txm', (QPath (Join-Path $PayloadRoot 'txm.bin'))
)

if ($ExtraQemuArgs -ne '') {
    $argsList += $ExtraQemuArgs.Split(' ')
}

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

$uartText = ''
$uartSha = $null
if ($serialBytes -gt 0) {
    $b = $null
    for ($retry = 0; $retry -lt 20 -and $null -eq $b; $retry++) {
        try {
            $b = [IO.File]::ReadAllBytes($serial)
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if ($null -ne $b) {
        $uartText = [Text.Encoding]::ASCII.GetString($b)
        $uartSha = (Get-FileHash $serial -Algorithm SHA256).Hash.ToLowerInvariant()
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
    dtree_path = $Dtree
    dtree_sha256 = (Get-FileHash $Dtree -Algorithm SHA256).Hash.ToLowerInvariant()
    bootkc_sha256 = (Get-FileHash (Join-Path $PayloadRoot 'bootkc.bin') -Algorithm SHA256).Hash.ToLowerInvariant()
    ramdisk_sha256 = (Get-FileHash (Join-Path $PayloadRoot 'ramdisk.dmg') -Algorithm SHA256).Hash.ToLowerInvariant()
    qemu_sha256 = (Get-FileHash $QemuExe -Algorithm SHA256).Hash.ToLowerInvariant()
    boot_args = $BootArgs
    serial_bytes = $serialBytes
    serial_sha256 = $uartSha
    elapsed_seconds = $elapsed
    natural_exit = $naturalExit
    exit_code = $exitCode
    stderr_bytes = [math]::Max(0, $stderrText.Length)
    stderr = $stderrText
}

$record | ConvertTo-Json -Depth 6 |
    Set-Content $result -Encoding UTF8

Write-Host ("RESULT: serial_bytes={0} natural_exit={1} exit={2}" -f
    $serialBytes, $naturalExit, $exitCode)
Write-Host "EVIDENCE: $RunRoot"
