# Convenience launcher for SNISPF on Windows (PowerShell).
# Right-click -> Run with PowerShell, or run from a terminal:
#     .\snispf.ps1 --auto -m combined

$ErrorActionPreference = "Stop"
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Dir

$ConfigArgs = @()
if (Test-Path (Join-Path $Dir "config.json")) {
    $ConfigArgs = @("--config", (Join-Path $Dir "config.json"))
}

$Candidates = @("snispf-windows-x86_64.exe", "snispf.exe")
foreach ($c in $Candidates) {
    $p = Join-Path $Dir $c
    if (Test-Path $p) {
        & $p @ConfigArgs @args
        exit $LASTEXITCODE
    }
}

if (Get-Command snispf -ErrorAction SilentlyContinue) {
    & snispf @ConfigArgs @args
    exit $LASTEXITCODE
}

if (Test-Path (Join-Path $Dir "run.py")) {
    & python (Join-Path $Dir "run.py") @ConfigArgs @args
    exit $LASTEXITCODE
}

Write-Error "Could not locate snispf.exe, system package, or run.py"
exit 1
