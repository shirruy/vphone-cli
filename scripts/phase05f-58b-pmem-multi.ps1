param([int]$MonitorPort = 4444, [int]$WarmupSeconds = 20, [string]$RunName = "58b-pmem-multi")
$ErrorActionPreference = 'Stop'
$RepoRoot = 'C:\Users\rbjos\source\vphone-cli-windows'
$QemuBuild = Join-Path $RepoRoot 'build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win'
$QemuExe = Join-Path $QemuBuild 'qemu-system-aarch64.exe'
$MingwBin = 'C:\msys64\mingw64\bin'
$PayloadRoot = Join-Path $env:USERPROFILE 'vphone-private\phase05f-known-good\payloads-v3'
$Dtree = Join-Path $RepoRoot 'build\phase05f-runtime\dt-fixtures\dtree_ascwrap.bin'
$RunRoot = Join-Path $RepoRoot "build\phase05f-runtime\$RunName"
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
Get-Process -Name 'qemu-system-aarch64' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$serial = Join-Path $RunRoot 'uart0.log'
function QPath([string]$p) { ([System.IO.Path]::GetFullPath($p)).Replace('\', '/') }
$argsList = @('-M','darwin','-bootkc',(QPath (Join-Path $PayloadRoot 'bootkc.bin')),'-dtree',(QPath $Dtree),'-tc',(QPath (Join-Path $PayloadRoot 'trustcache.bin')),'-ramdisk',(QPath (Join-Path $PayloadRoot 'ramdisk.dmg')),'-args','rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort','-display','none','-monitor',"tcp:127.0.0.1:$MonitorPort,server,nowait",'-chardev',("file,id=uart0,path="+(QPath $serial)),'-serial','chardev:uart0','-m','8G','-sptm',(QPath (Join-Path $PayloadRoot 'sptm.bin')),'-txm',(QPath (Join-Path $PayloadRoot 'txm.bin')))
$argString = ($argsList | ForEach-Object { if ($_ -match '\s' -and -not $_.StartsWith('"')) { '"'+$_+'"' } else { $_ } }) -join ' '
$oldPath = $env:PATH
try { $env:PATH = "$MingwBin;$oldPath"; $proc = Start-Process -FilePath $QemuExe -WorkingDirectory $QemuBuild -ArgumentList $argString -RedirectStandardOutput (Join-Path $RunRoot 'stdout.log') -RedirectStandardError (Join-Path $RunRoot 'stderr.log') -PassThru -WindowStyle Hidden } finally { $env:PATH = $oldPath }
$deadline = (Get-Date).AddSeconds($WarmupSeconds)
while ((Get-Date) -lt $deadline -and -not $proc.HasExited) { Start-Sleep -Milliseconds 500 }
$client = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $MonitorPort)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream); $writer.NewLine = "`n"
Start-Sleep -Milliseconds 300
$buf = New-Object byte[] 4096
while ($stream.DataAvailable) { $null = $stream.Read($buf,0,$buf.Length) }
$windows = @()
for ($i = 0; $i -lt 8; $i++) {
    $base = [uint64]0x10000000000 + [uint64]($i * 0x2000000)
    $f = Join-Path $RunRoot ("w{0}.bin" -f $i)
    $fp = $f.Replace('\','/')
    $cmd = 'pmemsave 0x' + $base.ToString('x') + ' 0x2000000 "' + $fp + '"'
    $writer.WriteLine($cmd)
    $writer.Flush()
    Start-Sleep -Seconds 6
}
$writer.WriteLine('quit'); $writer.Flush(); $client.Close()
try { [void]$proc.WaitForExit(15000) } catch {}
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
Write-Host 'dumps complete'
