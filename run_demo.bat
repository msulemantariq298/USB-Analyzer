@echo off
title USB Analyzer - 5-Scenario Attack Demo
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo Error: Virtual environment not found at .\venv.
    pause
    exit /b 1
)

set PYTHONPATH=%~dp0code
venv\Scripts\python.exe code\usb_analyzer\demo_runner.py
echo.
pause
