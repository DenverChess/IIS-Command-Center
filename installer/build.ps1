<#
.SYNOPSIS
  Builds the IIS Sentinel Windows installer (IISSentinel-Setup-<version>.exe).

.DESCRIPTION
  1. Downloads (and SHA-256 verifies) the CPython embeddable distribution and WinSW.
  2. Installs pip + requirements.txt into the embedded runtime, so the target machine needs no Python.
  3. Stages the application and smoke-tests every import with the bundled interpreter.
  4. Compiles installer\IISSentinel.iss with Inno Setup 6 (installed via winget / choco if missing).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File installer\build.ps1 -Version 2.0.0
#>
[CmdletBinding()]
param(
    [string]$Version = "2.0.0",
    [string]$OutputDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "dist"),
    [switch]$SkipCompile
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$PythonVersion = "3.12.10"
$Downloads = @{
    python = @{
        Url    = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
        Sha256 = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
    }
    winsw = @{
        Url    = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW.NET461.exe"
        Sha256 = "b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f"
    }
    getpip = @{
        Url    = "https://bootstrap.pypa.io/get-pip.py"
        Sha256 = $null
    }
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$AppSrc = Join-Path $RepoRoot "iis_sentinel"
$Work = Join-Path $PSScriptRoot "build"
$Cache = Join-Path $Work "cache"
$Stage = Join-Path $Work "stage"
$PyDir = Join-Path $Stage "python"
$AppDir = Join-Path $Stage "app"
$Py = Join-Path $PyDir "python.exe"

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

function Get-Verified([string]$name) {
    $d = $Downloads[$name]
    $file = Join-Path $Cache ([IO.Path]::GetFileName(([Uri]$d.Url).AbsolutePath))
    if (-not (Test-Path $file)) {
        Step "Downloading $($d.Url)"
        for ($i = 1; $i -le 4; $i++) {
            try { Invoke-WebRequest -UseBasicParsing -Uri $d.Url -OutFile $file; break }
            catch { if ($i -eq 4) { throw }; Start-Sleep -Seconds ([math]::Pow(2, $i + 1)) }
        }
    }
    if ($d.Sha256) {
        $actual = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
        if ($actual -ne $d.Sha256) {
            Remove-Item $file -Force
            throw "SHA-256 mismatch for $name : expected $($d.Sha256), got $actual"
        }
    }
    return $file
}

function Invoke-Checked([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe $($arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

Step "Preparing build directories"
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Cache, $PyDir, $AppDir, $OutputDir | Out-Null

Step "Staging embedded Python $PythonVersion"
Expand-Archive -Path (Get-Verified "python") -DestinationPath $PyDir -Force
$pth = Get-ChildItem $PyDir -Filter "python*._pth" | Select-Object -First 1
if (-not $pth) { throw "python*._pth not found in the embeddable distribution" }
$zipName = (Get-ChildItem $PyDir -Filter "python3*.zip" | Select-Object -First 1).Name
# The ._pth file pins sys.path: stdlib zip, the runtime dir, site-packages and the application directory.
Set-Content -Path $pth.FullName -Encoding ASCII -Value @($zipName, ".", "Lib\site-packages", "..\app", "import site")

Step "Installing pip and dependencies into the embedded runtime"
Invoke-Checked $Py @((Get-Verified "getpip"), "--no-warn-script-location", "--disable-pip-version-check")
Invoke-Checked $Py @("-m", "pip", "install", "--no-warn-script-location", "--disable-pip-version-check",
    "--prefer-binary", "-r", (Join-Path $AppSrc "requirements.txt"))

Step "Staging application"
$robo = robocopy $AppSrc $AppDir /E /NFL /NDL /NJH /NJS /NP /XD data __pycache__ .pytest_cache /XF *.pyc .gitignore
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
$global:LASTEXITCODE = 0
Copy-Item (Join-Path $PSScriptRoot "reset-password.cmd") $Stage
New-Item -ItemType Directory -Force -Path (Join-Path $Stage "service") | Out-Null
Copy-Item (Get-Verified "winsw") (Join-Path $Stage "service\IISSentinelService.exe")

Step "Smoke-testing the bundled runtime"
$env:SENTINEL_DATA_DIR = Join-Path $Work "smoke-data"
try {
    Invoke-Checked $Py @("-c", @"
import sys
import fastapi, uvicorn, websockets, sqlalchemy, aiosqlite, watchdog, psutil, ldap3, winrm, exchangelib, apscheduler
import win32crypt, win32wnet, win32serviceutil, pythoncom
import main, sentinelctl, remote_manager
from database import protect_secret, unprotect_secret
assert unprotect_secret(protect_secret('probe')) == 'probe', 'DPAPI round trip failed'
assert protect_secret('probe').startswith('dpapi:'), 'DPAPI not used'
print('runtime OK', sys.version)
"@)
}
finally {
    Remove-Item Env:\SENTINEL_DATA_DIR -ErrorAction SilentlyContinue
    if (Test-Path (Join-Path $Work "smoke-data")) { Remove-Item (Join-Path $Work "smoke-data") -Recurse -Force }
}
Invoke-Checked $Py @("-m", "compileall", "-q", "-j", "0", $AppDir)

if ($SkipCompile) { Write-Host "Staged at $Stage (compile skipped)"; return }

Step "Locating Inno Setup"
$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    if (Get-Command choco -ErrorAction SilentlyContinue) { choco install innosetup -y --no-progress | Out-Host }
    elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id JRSoftware.InnoSetup -e --silent --accept-package-agreements --accept-source-agreements | Out-Host
    }
    $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) { throw "Inno Setup 6 (ISCC.exe) not found. Install it from https://jrsoftware.org/isdl.php" }
}

Step "Compiling installer"
Invoke-Checked $iscc @("/Qp", "/DAppVersion=$Version", "/DStageDir=$Stage", "/DOutputDir=$OutputDir",
    (Join-Path $PSScriptRoot "IISSentinel.iss"))
$setup = Join-Path $OutputDir "IISSentinel-Setup-$Version.exe"
$hash = (Get-FileHash -Algorithm SHA256 $setup).Hash
Set-Content -Path "$setup.sha256" -Value "$hash  $(Split-Path -Leaf $setup)" -Encoding ASCII
Write-Host "Built $setup ($([math]::Round((Get-Item $setup).Length / 1MB, 1)) MB)  SHA-256 $hash" -ForegroundColor Green
Write-Host ""
Write-Host "  Run this file to install IIS Sentinel:" -ForegroundColor Cyan
Write-Host "    $setup" -ForegroundColor Cyan
Write-Host "  (installer\build\ only holds intermediate files; nothing in it is meant to be run.)" -ForegroundColor DarkGray
if ([Environment]::UserInteractive -and -not $env:CI) {
    Start-Process explorer.exe -ArgumentList "/select,`"$setup`""
}
