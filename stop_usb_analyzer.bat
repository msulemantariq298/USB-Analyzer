@echo off
title USB Analyzer - Shutdown Tool
cd /d "%~dp0"
echo ========================================================================
echo   Stopping any running USB Analyzer instances on port 8000...
echo ========================================================================

set found=0
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING 2^>nul') do (
    echo Terminating API process (PID %%a)...
    taskkill /F /PID %%a >nul 2>&1
    set found=1
)

if "%found%"=="1" (
    echo All USB Analyzer background instances have been terminated.
) else (
    echo No active USB Analyzer instances were found on port 8000.
)

echo.
pause
