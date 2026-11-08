@echo off
title USB Analyzer - Verification Test Suite
cd /d "%~dp0"
echo ========================================================================
echo   Running USB Analyzer Pytest Verification Suite
echo ========================================================================

if not exist "venv\Scripts\python.exe" (
    echo Error: Virtual environment not found at .\venv.
    pause
    exit /b 1
)

venv\Scripts\python.exe -m pytest code/tests -v
echo.
pause
