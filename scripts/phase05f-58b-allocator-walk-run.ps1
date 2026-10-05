# Phase 05F 58B: second-pass walk. Re-attaches GDB to a running QEMU
# (or starts a fresh boot), waits for enumeration to finish, then walks
# the captured allocator addresses from allocator-addresses.json.

param(
    [Parameter(Mandatory = $true)]
    [string]$RunName,       # run that has allocator-addresses.json

    [int]$GdbPort = 1235,
    [int]$BootSeconds = 25
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = 'C:\Users\rbjos\source\vphone-cli-windows'
$MingwBin = 'C:\msys64\mingw64\bin'
$GdbExe = Join-Path $MingwBin 'gdb-multiarch.exe'
$SrcRun = Join-Path $RepoRoot "build\phase05f-runtime\$RunName"
$ProbeScript = Join-Path $RepoRoot 'scripts\phase05f-58b-allocator-name-probe.py'

$addrFile = Join-Path $SrcRun 'allocator-addresses.json'
if (-not (Test-Path $addrFile)) { throw "missing $addrFile" }

# Copy the addresses into a fresh output dir so probe58b_walk writes there
$WalkRoot = Join-Path $SrcRun 'walk'
New-Item -ItemType Directory -Force -Path $WalkRoot | Out-Null
Copy-Item $addrFile (Join-Path $WalkRoot 'allocator-addresses.json') -Force

$gdbCmds = Join-Path $WalkRoot 'gdb.cmds'
$cmdLines = @(
    'set pagination off',
    'set confirm off',
    'set height 0',
    'set width 0',
    "target remote 127.0.0.1:$GdbPort",
    "source $($ProbeScript.Replace('\', '/'))",
    'probe58b_walk'
)
[System.IO.File]::WriteAllLines($gdbCmds, [string[]]$cmdLines, (New-Object System.Text.UTF8Encoding($false)))

$env:P2_OUT_DIR = $WalkRoot
$gdbLog = Join-Path $WalkRoot 'gdb-session.log'
Write-Host "Attaching GDB for walk pass..."
$gdbCmd = "`"$GdbExe`" --batch -x `"$gdbCmds`" 2>&1"
$gdbOutput = & cmd.exe /c $gdbCmd
$gdbExit = $LASTEXITCODE
$gdbOutput | Set-Content -LiteralPath $gdbLog -Encoding UTF8
Write-Host ("GDB exit={0}" -f $gdbExit)

$walkJson = Join-Path $WalkRoot 'allocator-walk.json'
if (Test-Path $walkJson) {
    Write-Host "WALK OUTPUT: $walkJson"
    Get-Content $walkJson | Select-Object -First 40
} else {
    Write-Host "NO WALK OUTPUT; check gdb-session.log"
    Get-Content $gdbLog | Select-Object -Last 30
}
