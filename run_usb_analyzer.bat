@echo off
setlocal
title USB Analyzer - Endpoint Defense System
cd /d "%~dp0"

echo ========================================================================
echo   USB ANALYZER - ENDPOINT DEFENSE SYSTEM
echo ========================================================================

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at .\venv.
    echo Please create it first using: py -m venv venv
    echo.
    pause
    exit /b 1
)

set PYTHONPATH=%~dp0code

echo [1/3] Starting Web API Server on http://127.0.0.1:8000 ...
start "USB Analyzer - Web API" /min "%~dp0venv\Scripts\python.exe" -m uvicorn usb_analyzer.api.main:app --host 127.0.0.1 --port 8000

echo [2/3] Waiting for server to initialize...
ping -n 4 127.0.0.1 >nul

echo [3/3] Opening Web Dashboard in default browser...
start http://127.0.0.1:8000/

echo.
echo ========================================================================
echo   Hardware Device Monitor is now ACTIVE.
echo   Connect any USB device to inspect security status in real-time.
echo.
echo   Press Ctrl+C anytime to stop monitoring.
echo ========================================================================
"%~dp0venv\Scripts\python.exe" -m usb_analyzer.device_monitor.windows

echo.
echo USB Analyzer session ended.
pause
