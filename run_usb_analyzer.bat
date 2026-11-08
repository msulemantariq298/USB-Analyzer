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

echo [1/4] Setting PYTHONPATH...
set PYTHONPATH=%~dp0code

echo [2/4] Checking for previous instances on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING 2^>nul') do (
    echo Freeing port 8000 from previous instance (PID %%a)...
    taskkill /F /PID %%a >nul 2>&1
)

echo [3/4] Launching API Server on http://127.0.0.1:8000 ...
start "USB Analyzer - Web API (Port 8000)" /min cmd /c "venv\Scripts\python.exe -m uvicorn usb_analyzer.api.main:app --host 127.0.0.1 --port 8000"

echo Waiting for API server to initialize...
timeout /t 3 /nobreak >nul

echo [4/4] Opening Web Dashboard in default browser...
start http://127.0.0.1:8000/

echo ========================================================================
echo   Launching Windows USB Device Monitor ^& Live Storage Scanner...
echo   Physical devices will be automatically recognized and categorized.
echo.
echo   Press Ctrl+C in this window anytime to stop monitoring.
echo ========================================================================
venv\Scripts\python.exe -m usb_analyzer.device_monitor.windows

echo.
echo ========================================================================
echo   Cleaning up background API server...
echo ========================================================================
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING 2^>nul') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo USB Analyzer stopped cleanly.
timeout /t 2 /nobreak >nul
