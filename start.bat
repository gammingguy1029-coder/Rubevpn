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

for %%B in (server.exe keygen.exe peercheck.exe speedtest.exe) do (
    if not exist "tools\userspace_wg\%%B" (
        echo [ERROR] Bundled binary missing: tools\userspace_wg\%%B
        echo Re-clone the repository with the binaries included.
        echo.
        pause
        exit /b 1
    )
)

echo.
echo Options:
echo   start.bat                    Start the tunnel stack (Pinggy relay)
echo   start-playit.bat             Start using the faster playit.gg relay
echo   start.bat --status           Show running state (read-only)
echo   start.bat --list-devices     List enrolled devices
echo   start.bat --add-device NAME  Enroll a new device
echo   start.bat --remove-device ID Revoke a device
echo.
echo Relay: set RUBEVPN_TUNNEL_PROVIDER=pinggy (default) or playit.
echo For playit, run: python scripts\setup_playit.py --secret KEY --endpoint host:port
echo.

if "%~1"=="" (
    echo Starting RubeVPN experimental WireGuard + UDP tunnel...
) else (
    echo Running: python scripts\start_experimental.py %*
)

python scripts\start_experimental.py %*
set EXITCODE=%ERRORLEVEL%

echo.
if not "%~1"=="" goto :done
echo Tip: enroll another device with: start.bat --add-device Laptop
:done
if not "%EXITCODE%"=="0" echo [ERROR] Command failed with exit code %EXITCODE%. Check the logs in the RubeVPN config directory.
echo.
pause
exit /b %EXITCODE%
