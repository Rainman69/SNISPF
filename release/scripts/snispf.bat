@echo off
REM Convenience launcher for SNISPF on Windows (cmd.exe).
REM Place this file next to snispf.exe (or use a system-installed snispf)
REM and just double-click it.

setlocal
set DIR=%~dp0
set CONFIG=
if exist "%DIR%config.json" set CONFIG=--config "%DIR%config.json"

REM 1) Prefer the bundled standalone binary
if exist "%DIR%snispf-windows-x86_64.exe" (
    "%DIR%snispf-windows-x86_64.exe" %CONFIG% %*
    goto :eof
)
if exist "%DIR%snispf.exe" (
    "%DIR%snispf.exe" %CONFIG% %*
    goto :eof
)

REM 2) Fall back to system-installed snispf
where snispf >nul 2>nul
if %ERRORLEVEL%==0 (
    snispf %CONFIG% %*
    goto :eof
)

REM 3) Fall back to running from source
if exist "%DIR%run.py" (
    python "%DIR%run.py" %CONFIG% %*
    goto :eof
)

echo ERROR: could not locate snispf.exe, system package, or run.py
exit /b 1
