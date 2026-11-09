@echo off
setlocal
title USB Analyzer - Stop Protection
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at .\venv.
    pause
    exit /b 1
)

set PYTHONPATH=%~dp0code
"%~dp0venv\Scripts\python.exe" -m usb_analyzer.service stop
