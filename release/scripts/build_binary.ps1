# Build a standalone single-file SNISPF executable on Windows.
# Output:  dist\snispf-windows-<arch>.exe
#
# Usage (in PowerShell):  .\release\scripts\build_binary.ps1
# Needs:                  Python 3.8+ from python.org (in PATH)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $ProjectRoot

$Arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
$OutName = "snispf-windows-$Arch"

Write-Host "[*] Building $OutName ..." -ForegroundColor Cyan

python -m pip install --upgrade pip wheel | Out-Null
python -m pip install --upgrade pyinstaller | Out-Null
python -m pip install . | Out-Null

python -m PyInstaller `
    --onefile `
    --name $OutName `
    --console `
    --clean `
    --noconfirm `
    --collect-all sni_spoofing `
    --add-data "config.json;." `
    run.py

Write-Host ""
Write-Host "[+] Done. Binary at: dist\$OutName.exe" -ForegroundColor Green
Write-Host "    Run with:  .\dist\$OutName.exe --help"
