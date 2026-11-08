@echo off
title USB Analyzer - Shutdown Tool
cd /d "%~dp0"
echo ========================================================================
echo   Stopping any running USB Analyzer instances...
echo ========================================================================

taskkill /F /FI "WINDOWTITLE eq USB Analyzer*" >nul 2>&1

if exist "venv\Scripts\python.exe" (
    "%~dp0venv\Scripts\python.exe" -c "import socket, os, subprocess; [subprocess.run(['taskkill', '/F', '/PID', line.split()[-1]], capture_output=True) for line in subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout.splitlines() if ':8000 ' in line and 'LISTENING' in line]" >nul 2>&1
)

echo.
echo USB Analyzer processes have been stopped.
echo.
pause
