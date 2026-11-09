@echo off
setlocal
title USB Analyzer - Background Defense Service
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at .\venv.
    echo Please create it first using: py -m venv venv
    echo.
    pause
    exit /b 1
)

set PYTHONPATH=%~dp0code
"%~dp0venv\Scripts\python.exe" -m usb_analyzer.service start

