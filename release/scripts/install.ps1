# One-line installer for SNISPF on Windows.
# Downloads the latest release .exe and drops it (plus a default config.json)
# into %LOCALAPPDATA%\SNISPF, then adds that folder to the user PATH.
#
# Usage (PowerShell, as your normal user):
#   iwr -useb https://raw.githubusercontent.com/Rainman69/SNISPF/main/release/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"
$Repo = "Rainman69/SNISPF"
$InstallDir = Join-Path $env:LOCALAPPDATA "SNISPF"

if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }

$Arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
$Asset = "snispf-windows-$Arch.exe"

Write-Host "[*] Looking up the latest SNISPF release..." -ForegroundColor Cyan
$Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
                             -Headers @{ "User-Agent" = "snispf-installer" }
$Tag = $Release.tag_name
$Url = "https://github.com/$Repo/releases/download/$Tag/$Asset"

Write-Host "[*] Downloading $Asset ($Tag)..." -ForegroundColor Cyan
$ExePath = Join-Path $InstallDir "snispf.exe"
Invoke-WebRequest -Uri $Url -OutFile $ExePath -UseBasicParsing

$CfgPath = Join-Path $InstallDir "config.json"
if (-not (Test-Path $CfgPath)) {
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$Repo/$Tag/config.json" `
                          -OutFile $CfgPath -UseBasicParsing
    } catch { }
}

# Add to user PATH if missing
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($UserPath -split ";") -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    Write-Host "[*] Added $InstallDir to user PATH (open a new terminal to use it)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[+] Installed to $ExePath" -ForegroundColor Green
Write-Host "    Default config: $CfgPath"
Write-Host "    Try:  snispf --help"
