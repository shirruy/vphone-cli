# Phase 05F 58B: physical-memory DT scan via QEMU monitor pmemsave.
# Dumps DRAM regions and searches offline for DT compatible strings.

param(
    [Parameter(Mandatory = $true)]
    [string]$RunName,

    [int]$MonitorPort = 4444,
    [int]$WarmupSeconds = 20
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$QemuBuild = Join-Path $RepoRoot 'build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win'
$QemuExe = Join-Path $QemuBuild 'qemu-system-aarch64.exe'
$MingwBin = 'C:\msys64\mingw64\bin'
$PayloadRoot = Join-Path $env:USERPROFILE 'vphone-private\phase05f-known-good\payloads-v3'
$Dtree = Join-Path $RepoRoot 'build\phase05f-runtime\dt-fixtures\dtree_ascwrap.bin'
$RunRoot = Join-Path $RepoRoot "build\phase05f-runtime\$RunName"
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

Get-Process -Name 'qemu-system-aarch64' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

$serial = Join-Path $RunRoot 'uart0.log'
$so = Join-Path $RunRoot 'stdout.log'
$se = Join-Path $RunRoot 'stderr.log'
function QPath([string]$p) { ([System.IO.Path]::GetFullPath($p)).Replace('\', '/') }

$argsList = @(
    '-M','darwin',
    '-bootkc', (QPath (Join-Path $PayloadRoot 'bootkc.bin')),
    '-dtree', (QPath $Dtree),
    '-tc', (QPath (Join-Path $PayloadRoot 'trustcache.bin')),
    '-ramdisk', (QPath (Join-Path $PayloadRoot 'ramdisk.dmg')),
    '-args', 'rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort',
    '-display','none',
    '-monitor', "tcp:127.0.0.1:$MonitorPort,server,nowait",
    '-chardev', ("file,id=uart0,path=" + (QPath $serial)),
    '-serial','chardev:uart0',
    '-m','8G',
    '-sptm', (QPath (Join-Path $PayloadRoot 'sptm.bin')),
    '-txm', (QPath (Join-Path $PayloadRoot 'txm.bin'))
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
Write-Host ("QEMU PID {0}; warmup {1}s..." -f $proc.Id, $WarmupSeconds)

$deadline = (Get-Date).AddSeconds($WarmupSeconds)
while ((Get-Date) -lt $deadline -and -not $proc.HasExited) { Start-Sleep -Milliseconds 500 }
if ($proc.HasExited) { throw "qemu exited: $($proc.ExitCode)" }

# pmemsave via TCP monitor
$dumpFile = Join-Path $RunRoot 'dram-head-64mb.bin'
Write-Host "Dumping first 64MB of DRAM (0x10000000000) via pmemsave..."
$client = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $MonitorPort)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.NewLine = "`n"
Start-Sleep -Milliseconds 300
# drain any banner
$buf = New-Object byte[] 4096
while ($stream.DataAvailable) { $null = $stream.Read($buf, 0, $buf.Length) }
$writer.WriteLine("pmemsave 0x10000000000 0x4000000 `"$($dumpFile.Replace('\','/'))`"")
$writer.Flush()
Start-Sleep -Seconds 8
$respBytes = New-Object System.Collections.Generic.List[byte]
while ($stream.DataAvailable) {
    $n = $stream.Read($buf, 0, $buf.Length)
    for ($k = 0; $k -lt $n; $k++) { $respBytes.Add($buf[$k]) }
}
$resp = [System.Text.Encoding]::ASCII.GetString($respBytes.ToArray())
$writer.WriteLine('info status')
$writer.Flush()
Start-Sleep -Milliseconds 500
while ($stream.DataAvailable) {
    $n = $stream.Read($buf, 0, $buf.Length)
    for ($k = 0; $k -lt $n; $k++) { $respBytes.Add($buf[$k]) }
}
$resp = [System.Text.Encoding]::ASCII.GetString($respBytes.ToArray())
$writer.WriteLine('quit')
$writer.Flush()
$client.Close()
Write-Host "monitor resp: $resp"

try { [void]$proc.WaitForExit(10000) } catch {}
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }

if (-not (Test-Path $dumpFile)) { throw "dump file not created" }
$dumpSize = (Get-Item $dumpFile).Length
Write-Host ("dump size: {0}" -f $dumpSize)

# Offline search
$needles = @('iop,ascwrap-v6','iop-nub,rtbuddy-v2','iop,ascwrap-v7','ANS2','arm-io','uart0')
$bytes = [System.IO.File]::ReadAllBytes($dumpFile)
$results = @{}
foreach ($n in $needles) {
    $needle = [System.Text.Encoding]::ASCII.GetBytes($n)
    $count = 0
    $firstOffsets = @()
    for ($i = 0; $i -le $bytes.Length - $needle.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $needle.Length; $j++) {
            if ($bytes[$i + $j] -ne $needle[$j]) { $match = $false; break }
        }
        if ($match) {
            $count++
            if ($firstOffsets.Count -lt 10) { $firstOffsets += ('0x{0:x}' -f (0x10000000000 + $i)) }
        }
    }
    $results[$n] = @{ count = $count; first = $firstOffsets }
    Write-Host ("{0}: {1} hits {2}" -f $n, $count, ($firstOffsets -join ' '))
}

$out = [ordered]@{
    gate = '58B_PHYSICAL_DT_SCAN'
    dump = 'dram-head-64mb.bin'
    dump_size = $dumpSize
    results = $results
}
$out | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $RunRoot 'pmem-dt-scan.json') -Encoding UTF8
