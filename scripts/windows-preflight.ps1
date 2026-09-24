$ErrorActionPreference = "Continue"

$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

Write-Host "=== VPhone Windows Port Preflight ==="
Write-Host "OS: $($os.Caption) $($os.Version)"
Write-Host "CPU: $($cpu.Name)"
Write-Host "Architecture env: $env:PROCESSOR_ARCHITECTURE"

$whpx = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
if ($whpx) { Write-Host "Windows Hypervisor Platform: $($whpx.State)" }
else { Write-Host "Windows Hypervisor Platform: UNKNOWN" }

foreach ($cmd in @("git", "cmake", "ninja", "clang", "qemu-system-aarch64", "swift")) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($found) { Write-Host "$cmd: FOUND at $($found.Source)" }
    else { Write-Host "$cmd: MISSING" }
}

Write-Host ""
Write-Host "Interpretation:"
Write-Host "- x64 Windows can use QEMU TCG for ARM64 correctness research, not native ARM64 WHPX acceleration."
Write-Host "- Windows ARM64 is the candidate host for WHPX-accelerated ARM64 after correctness is proven."
