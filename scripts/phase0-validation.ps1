$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    Write-Host ""
    Write-Host $Label -ForegroundColor Yellow
    & $Action

    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

Set-Location (Resolve-Path (Join-Path $PSScriptRoot ".."))

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VPHONE WINDOWS PORT - PHASE 0 VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$branch = (git branch --show-current).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to resolve current Git branch."
}

if ($branch -ne "windows-port") {
    throw "PHASE 0 FAIL: expected branch windows-port, found $branch"
}

$dirty = git status --porcelain
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read Git status."
}

if ($dirty) {
    throw "PHASE 0 FAIL: working tree is not clean before validation."
}

$head = (git rev-parse HEAD).Trim()
Write-Host "Branch : $branch" -ForegroundColor Green
Write-Host "HEAD   : $head" -ForegroundColor Green

Invoke-Checked -Label "[1/5] Windows environment preflight" -Action {
    & "$PSScriptRoot\windows-preflight.ps1"
}

Invoke-Checked -Label "[2/5] CMake configure" -Action {
    if (Test-Path ".\build\windows") {
        Remove-Item ".\build\windows" -Recurse -Force
    }
    cmake -S ".\windows" -B ".\build\windows"
}

Invoke-Checked -Label "[3/5] Release build" -Action {
    cmake --build ".\build\windows" --config Release
}

Invoke-Checked -Label "[4/5] CTest contract suite" -Action {
    ctest --test-dir ".\build\windows" -C Release --output-on-failure
}

$exe = Get-ChildItem -Path ".\build\windows" -Filter "vphone-vm-win.exe" -File -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $exe) {
    throw "PHASE 0 FAIL: vphone-vm-win.exe was not produced."
}

Write-Host ""
Write-Host "[5/5] Capability contract" -ForegroundColor Yellow
$capabilityJson = & $exe.FullName --capabilities
if ($LASTEXITCODE -ne 0) {
    throw "PHASE 0 FAIL: capability probe exited with $LASTEXITCODE"
}

try {
    $capabilities = $capabilityJson | ConvertFrom-Json
}
catch {
    throw "PHASE 0 FAIL: capability output is not valid JSON."
}

if ($capabilities.backend -ne "windows-research-stub") {
    throw "PHASE 0 FAIL: unexpected backend '$($capabilities.backend)'"
}

if ($capabilities.persistent_storage -ne "supported") {
    throw "PHASE 0 FAIL: persistent_storage contract unexpectedly changed."
}

$mustRemainUnknown = @(
    "arm64_execution",
    "apple_machine_model",
    "serial_console",
    "display",
    "input",
    "guest_transport",
    "sep_model"
)

foreach ($name in $mustRemainUnknown) {
    if ($capabilities.$name -ne "unknown") {
        throw "PHASE 0 FAIL: $name must remain unknown until runtime evidence exists. Found '$($capabilities.$name)'."
    }
}

$capabilityJson | Write-Host

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " PHASE 0 VALIDATION PASS" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "This proves only the Windows scaffold, CLI contract, build, and test harness."
Write-Host "It does NOT prove iOS boot, Apple PV devices, SEP, graphics, input, or SpringBoard."
