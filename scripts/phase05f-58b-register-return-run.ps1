param([Parameter(Mandatory = $true)][string]$RunName, [int]$GdbPort = 1246)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$QemuBuild = Join-Path $RepoRoot 'build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win'
$QemuExe = Join-Path $QemuBuild 'qemu-system-aarch64.exe'
$MingwBin = 'C:\msys64\mingw64\bin'
$GdbExe = Join-Path $MingwBin 'gdb-multiarch.exe'
$PayloadRoot = Join-Path $env:USERPROFILE 'vphone-private\phase05f-known-good\payloads-v3'
$Dtree = Join-Path $RepoRoot 'build\phase05f-runtime\dt-fixtures\dtree_ascwrap.bin'
$ProbeScript = Join-Path $RepoRoot 'scripts\phase05f-58b-register-return-probe.py'
$RunRoot = Join-Path $RepoRoot "build\phase05f-runtime\$RunName"
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
Get-Process -Name 'qemu-system-aarch64' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

function QPath([string]$p) { ([System.IO.Path]::GetFullPath($p)).Replace('\', '/') }
$argsList = @('-M','darwin','-bootkc',(QPath (Join-Path $PayloadRoot 'bootkc.bin')),'-dtree',(QPath $Dtree),'-tc',(QPath (Join-Path $PayloadRoot 'trustcache.bin')),'-ramdisk',(QPath (Join-Path $PayloadRoot 'ramdisk.dmg')),'-args','rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort','-display','none','-monitor','none','-chardev',("file,id=uart0,path="+(QPath (Join-Path $RunRoot 'uart0.log'))),'-serial','chardev:uart0','-m','8G','-sptm',(QPath (Join-Path $PayloadRoot 'sptm.bin')),'-txm',(QPath (Join-Path $PayloadRoot 'txm.bin')),'-gdb',"tcp:127.0.0.1:$GdbPort",'-S')
$argString = ($argsList | ForEach-Object { if ($_ -match '\s' -and -not $_.StartsWith('"')) { '"'+$_+'"' } else { $_ } }) -join ' '
$oldPath = $env:PATH
try { $env:PATH = "$MingwBin;$oldPath"; $proc = Start-Process -FilePath $QemuExe -WorkingDirectory $QemuBuild -ArgumentList $argString -RedirectStandardOutput (Join-Path $RunRoot 'stdout.log') -RedirectStandardError (Join-Path $RunRoot 'stderr.log') -PassThru -WindowStyle Hidden } finally { $env:PATH = $oldPath }
Write-Host ("QEMU PID {0}" -f $proc.Id)

$gdbCmds = Join-Path $RunRoot 'gdb.cmds'
$cmdLines = @('set pagination off','set confirm off','set height 0','set width 0',"target remote 127.0.0.1:$GdbPort","source $($ProbeScript.Replace('\','/'))",'probe58j')
[System.IO.File]::WriteAllLines($gdbCmds, [string[]]$cmdLines, (New-Object System.Text.UTF8Encoding($false)))
$env:P2_OUT_DIR = $RunRoot
$gdbCmd = "`"$GdbExe`" --batch -x `"$gdbCmds`" 2>&1"
$out = & cmd.exe /c $gdbCmd
$out | Set-Content -LiteralPath (Join-Path $RunRoot 'gdb-session.log') -Encoding UTF8
if (-not $proc.HasExited) { & taskkill /F /T /PID $proc.Id 2>$null | Out-Null; Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
$pj = Join-Path $RunRoot 'register-return.json'
if (Test-Path $pj) { Get-Content $pj | Select-Object -First 80 } else { Get-Content (Join-Path $RunRoot 'gdb-session.log') | Select-Object -Last 25 }
