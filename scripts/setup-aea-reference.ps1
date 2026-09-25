param(
    [Parameter(Mandatory = $true)][string]$VenvPath
)

$ErrorActionPreference = "Stop"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python is required for independent AEA interoperability proof."
}

$versionJson = & python -c "import json,sys; print(json.dumps({'major':sys.version_info.major,'minor':sys.version_info.minor,'bits':__import__('struct').calcsize('P')*8}))"
if ($LASTEXITCODE -ne 0) {
    throw "Python version probe failed."
}

$version = $versionJson | ConvertFrom-Json

if ($version.major -ne 3 -or $version.minor -lt 11 -or $version.minor -gt 14) {
    throw "Python 3.11 through 3.14 is required. Found $($version.major).$($version.minor)."
}

if ($version.bits -ne 64) {
    throw "64-bit Python is required for the pinned Windows pyliblzfse wheel."
}

$tag = "cp$($version.major)$($version.minor)"
$wheelName = "pyliblzfse-0.4.1-$tag-$tag-win_amd64.whl"
$wheelUrl = "https://raw.githubusercontent.com/abrignoni/iLEAPP/main/whl_files/$wheelName"

if (Test-Path $VenvPath) {
    Remove-Item $VenvPath -Recurse -Force
}

& python -m venv $VenvPath
if ($LASTEXITCODE -ne 0) {
    throw "Could not create AEA reference virtual environment."
}

$venvPython = Join-Path $VenvPath "Scripts\python.exe"
$wheelPath = Join-Path $VenvPath $wheelName

& $venvPython -m pip install --disable-pip-version-check --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "pip upgrade failed."
}

Invoke-WebRequest -Uri $wheelUrl -OutFile $wheelPath

& $venvPython -m pip install --disable-pip-version-check $wheelPath
if ($LASTEXITCODE -ne 0) {
    throw "Pinned pyliblzfse wheel install failed."
}

& $venvPython -m pip install --disable-pip-version-check "cryptography" "lz4"
if ($LASTEXITCODE -ne 0) {
    throw "Independent AEA Python dependencies failed to install."
}

& $venvPython -m pip install --disable-pip-version-check --no-deps "git+https://github.com/kinnay/AEA.git@d22f4fdf620436d12f1a893bbb11b90ac52fa646"
if ($LASTEXITCODE -ne 0) {
    throw "Pinned kinnay/AEA reference install failed."
}

& $venvPython -c "from aea import aea; print('REFERENCE_AEA_IMPORT_PASS')"
if ($LASTEXITCODE -ne 0) {
    throw "Independent AEA reference import failed."
}

Write-Host "AEA reference environment ready: $venvPython" -ForegroundColor Green
