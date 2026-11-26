@echo off
title RubeVPN Stop
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python 3.12+ is required. Install it from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

python scripts\start_experimental.py --stop
set EXITCODE=%ERRORLEVEL%

echo.
if "%EXITCODE%"=="0" (
    echo RubeVPN stack stopped.
) else (
    echo [ERROR] Stop failed with exit code %EXITCODE%.
)

echo.
echo Current state:
python scripts\start_experimental.py --status
echo.
pause
exit /b %EXITCODE%
