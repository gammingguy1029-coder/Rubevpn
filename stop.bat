@echo off
title RubeVPN Stop
cd /d "%~dp0"
python scripts\start_experimental.py --stop
echo.
pause
