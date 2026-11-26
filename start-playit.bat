@echo off
title RubeVPN Start (playit.gg)
cd /d "%~dp0"

echo.
echo Starting RubeVPN with the playit.gg UDP relay...
echo Make sure you have run:
echo   python scripts\setup_playit.py --secret KEY --endpoint host:port
echo.

set RUBEVPN_TUNNEL_PROVIDER=playit
python scripts\start_experimental.py --provider playit %*
set EXITCODE=%ERRORLEVEL%

echo.
pause
exit /b %EXITCODE%
