@echo off
rem Create or reset the IIS Sentinel break-glass administrator. Takes effect immediately (no service restart).
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
set "SENTINEL_DATA_DIR=%ProgramData%\IIS Sentinel"
"%~dp0python\python.exe" "%~dp0app\sentinelctl.py" set-admin-password %*
pause
