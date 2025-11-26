@echo off
echo Starting Enhanced Host-Based Firewall...
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Run the startup script
python start_firewall.py

pause
