@echo off
chcp 65001 >nul
setlocal
if "%~1"=="" (
    echo drop the dll
    pause
    exit /b 1
)
icacls "%~dp1." /grant "*S-1-15-2-1:(OI)(CI)(RX)" >nul
icacls "%~f1" /grant "*S-1-15-2-1:(RX)" >nul
if errorlevel 1 (
    echo error
) else (
    echo done: %~nx1
)
pause
