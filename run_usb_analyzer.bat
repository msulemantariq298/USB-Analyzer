@echo off
title USB Analyzer - Endpoint Defense System
echo ========================================================================
echo   Starting USB Analyzer (API Server + Windows Device Monitor)
echo ========================================================================
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo Error: Virtual environment not found at .\venv.
    echo Please create it first: py -m venv venv
    pause
    exit /b 1
)

echo [1/3] Setting PYTHONPATH...
set PYTHONPATH=%~dp0code

echo [2/3] Launching API Server on http://127.0.0.1:8000 ...
start "USB Analyzer - Web API (Port 8000)" /min cmd /c "venv\Scripts\python.exe -m uvicorn usb_analyzer.api.main:app --host 127.0.0.1 --port 8000"

echo Waiting for API server to start...
timeout /t 3 /nobreak >nul

echo [3/3] Opening Web Dashboard in default browser...
start http://127.0.0.1:8000/

echo ========================================================================
echo   Launching Windows USB Device Monitor ^& Live Storage Scanner...
echo   Insert any USB device now to automatically inspect and defend!
echo   (Press Ctrl+C in this window anytime to stop monitoring)
echo ========================================================================
venv\Scripts\python.exe -m usb_analyzer.device_monitor.windows
