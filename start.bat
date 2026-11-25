@echo off
title RubeVPN Start
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python 3.12+ is required. Install it from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)"
if errorlevel 1 (
    echo [ERROR] Python 3.12+ is required; the installed version is older.
    echo.
    pause
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js/npm is required for the public UDP tunnel.
    echo Install it from https://nodejs.org/ and rerun this file.
    echo.
    pause
    exit /b 1
)

if not exist "tools\userspace_wg\server.exe" (
    echo [ERROR] Bundled binaries are missing: tools\userspace_wg\server.exe
    echo Re-clone the repository with the binaries included.
    echo.
    pause
    exit /b 1
)

echo.
echo Starting RubeVPN experimental WireGuard + UDP tunnel...
python scripts\start_experimental.py
echo.
pause
