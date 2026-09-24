$ErrorActionPreference = "Stop"

function Find-Command([string]$Name) {
    return Get-Command $Name -ErrorAction SilentlyContinue
}

function Write-CommandStatus([string]$Name, [bool]$Required) {
    $found = Find-Command $Name
    $kind = if ($Required) { "REQUIRED" } else { "OPTIONAL" }

    if ($found) {
        Write-Host ("{0}: FOUND at {1} [{2}]" -f $Name, $found.Source, $kind) -ForegroundColor Green
        return $true
    }

    $color = if ($Required) { "Red" } else { "Yellow" }
    Write-Host ("{0}: MISSING [{1}]" -f $Name, $kind) -ForegroundColor $color
    return (-not $Required)
}

Write-Host "=== VPhone Windows Port Preflight ===" -ForegroundColor Cyan

$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

Write-Host "OS: $($os.Caption) $($os.Version)"
Write-Host "CPU: $($cpu.Name)"
Write-Host "Architecture env: $env:PROCESSOR_ARCHITECTURE"

try {
    $whpx = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction Stop
    Write-Host "Windows Hypervisor Platform: $($whpx.State)"
}
catch {
    Write-Host "Windows Hypervisor Platform: UNKNOWN ($($_.Exception.Message))" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Tool inventory:" -ForegroundColor Cyan

$requiredOk = $true
foreach ($cmd in @("git", "cmake")) {
    if (-not (Write-CommandStatus -Name $cmd -Required $true)) {
        $requiredOk = $false
    }
}

foreach ($cmd in @("ninja", "clang", "qemu-system-aarch64", "swift")) {
    [void](Write-CommandStatus -Name $cmd -Required $false)
}

$pf86 = [Environment]::GetFolderPath("ProgramFilesX86")
$vswhere = Join-Path $pf86 "Microsoft Visual Studio\Installer\vswhere.exe"
$msvcPath = $null

if (Test-Path $vswhere) {
    $msvcPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}

if ($msvcPath) {
    Write-Host "MSVC Build Tools: FOUND at $msvcPath [REQUIRED]" -ForegroundColor Green
}
else {
    Write-Host "MSVC Build Tools: MISSING [REQUIRED]" -ForegroundColor Red
    $requiredOk = $false
}

Write-Host ""
Write-Host "Interpretation:" -ForegroundColor Cyan
Write-Host "- x64 Windows can use QEMU TCG for ARM64 correctness research."
Write-Host "- Windows ARM64 is the candidate host for WHPX-accelerated ARM64 after correctness is proven."
Write-Host "- QEMU, Clang, Ninja, and Swift are optional for Phase 0 and become relevant in later phases."

if (-not $requiredOk) {
    Write-Host ""
    Write-Host "PREFLIGHT FAIL: one or more Phase 0 required dependencies are missing." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "PREFLIGHT PASS" -ForegroundColor Green
exit 0
