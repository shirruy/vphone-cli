# Phase 05F Iteration 58B: ANS MMIO boot probe.
#
# Boots the canonical ascwrap DT fixture with the new apple-ans device
# and captures the first QEMU-visible ANS hardware primitives.
#
# Evidence outputs in build\phase05f-runtime\<RunName>\:
#   uart0.log    - guest serial
#   stderr.log   - apple-ans MMIO trace lines (apple-ans: ...)
#   stdout.log   - QEMU stdout
#   result.json  - manifest with SHAs and gate verdicts

param(
    [Parameter(Mandatory = $true)]
    [string]$RunName,

    [int]$RunSeconds = 60
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = 'C:\Users\rbjos\source\vphone-cli-windows'
$QemuBuild = Join-Path $RepoRoot 'build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win'
$QemuExe = Join-Path $QemuBuild 'qemu-system-aarch64.exe'
$MingwBin = 'C:\msys64\mingw64\bin'
$PayloadRoot = Join-Path $env:USERPROFILE 'vphone-private\phase05f-known-good\payloads-v3'
$Dtree = Join-Path $RepoRoot 'build\phase05f-runtime\dt-fixtures\dtree_ascwrap.bin'
$ExpectedDtreeSha = 'CE06C3379F50E6E9FBB60D2EA0FBA6733F0FF2784C3E4E11AA7EC0F2F07D8868'

$RunRoot = Join-Path $RepoRoot "build\phase05f-runtime\$RunName"
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

Get-Process -Name 'qemu-system-aarch64' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# Gate 1: canonical DT fixture identity
$dtreeSha = (Get-FileHash $Dtree -Algorithm SHA256).Hash
if ($dtreeSha -ne $ExpectedDtreeSha) {
    throw "dtree fixture SHA mismatch: got $dtreeSha expected $ExpectedDtreeSha"
}
Write-Host ("dtree fixture SHA verified: {0}" -f $dtreeSha.Substring(0,8))

$serial = Join-Path $RunRoot 'uart0.log'
$so = Join-Path $RunRoot 'stdout.log'
$se = Join-Path $RunRoot 'stderr.log'

function QPath([string]$p) {
    return ([System.IO.Path]::GetFullPath($p)).Replace('\', '/')
}

$BootArgs = 'rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort kextlog=0xffff'
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
    '-txm', (QPath (Join-Path $PayloadRoot 'txm.bin'))
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
Write-Host ("QEMU PID {0}, running {1}s..." -f $proc.Id, $RunSeconds)

$deadline = (Get-Date).AddSeconds($RunSeconds)
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    Start-Sleep -Milliseconds 1000
}

if (-not $proc.HasExited) {
    & taskkill /F /T /PID $proc.Id 2>$null | Out-Null
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    try { [void]$proc.WaitForExit(10000) } catch {}
}
$proc.Refresh()
Write-Host ("QEMU exit={0}" -f $proc.ExitCode)

# Gates
$stderrContent = ''
if (Test-Path $se) { $stderrContent = Get-Content $se -Raw }
$ansMapped = [bool]($stderrContent -match 'apple-ans: mmio\[0\] mapped')
$ansRead = [bool]($stderrContent -match 'apple-ans: read')
$ansWrite = [bool]($stderrContent -match 'apple-ans: write')
$ansReadCount = ([regex]::Matches($stderrContent, 'apple-ans: read')).Count
$ansWriteCount = ([regex]::Matches($stderrContent, 'apple-ans: write')).Count
$serialBytes = 0
if (Test-Path $serial) { $serialBytes = (Get-Item $serial).Length }

$serialContent = ''
if (Test-Path $serial) { $serialContent = Get-Content $serial -Raw }
$serialHasANS = [bool]($serialContent -match '(?i)AppleANS|ASCWrap|ANS2')

$record = [ordered]@{
    run_name = $RunName
    stamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
    iteration = '58B'
    dtree_sha256 = $dtreeSha.ToLowerInvariant()
    qemu_exe_sha256 = (Get-FileHash $QemuExe -Algorithm SHA256).Hash.ToLowerInvariant()
    run_seconds = $RunSeconds
    serial_bytes = $serialBytes
    gates = [ordered]@{
        ans_mmio_mapped = $ansMapped
        ans_read_observed = $ansRead
        ans_write_observed = $ansWrite
        ans_read_count = $ansReadCount
        ans_write_count = $ansWriteCount
        serial_ans_driver_output = $serialHasANS
    }
}
$record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $RunRoot 'result.json') -Encoding UTF8

Write-Host ''
Write-Host '=== 58B GATES ==='
Write-Host ("ans_mmio_mapped       = {0}" -f $ansMapped)
Write-Host ("ans_read_observed     = {0} ({1} reads)" -f $ansRead, $ansReadCount)
Write-Host ("ans_write_observed    = {0} ({1} writes)" -f $ansWrite, $ansWriteCount)
Write-Host ("serial_ans_driver     = {0}" -f $serialHasANS)
Write-Host ("serial_bytes          = {0}" -f $serialBytes)
