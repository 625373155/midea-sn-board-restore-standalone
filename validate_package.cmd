@echo off
setlocal
cd /d "%~dp0"
py -3 "%~dp0midea_sn_restore_cli.py" validate %*
set "EXIT_CODE=%ERRORLEVEL%"
echo.
pause
exit /b %EXIT_CODE%
