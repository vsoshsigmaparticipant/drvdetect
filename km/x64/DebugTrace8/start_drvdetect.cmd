@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "DRIVER=%SCRIPT_DIR%\km.sys"
set "CERT=%SCRIPT_DIR%\km.cer"
set "MONITOR=%SCRIPT_DIR%\..\..\..\um\x64\Debug\um.exe"
set "SERVICE=DrvDetect"

echo [drvdetect] checking admin rights...
net session >nul 2>&1
if errorlevel 1 (
    echo [drvdetect] run this script from an elevated Command Prompt.
    exit /b 1
)

if not exist "%DRIVER%" (
    echo [drvdetect] driver not found: %DRIVER%
    exit /b 1
)

if not exist "%CERT%" (
    echo [drvdetect] certificate not found: %CERT%
    exit /b 1
)

if not exist "%MONITOR%" (
    echo [drvdetect] monitor not found: %MONITOR%
    exit /b 1
)

echo [drvdetect] adding test certificate...
certutil -addstore Root "%CERT%" >nul
if errorlevel 1 (
    echo [drvdetect] failed to add certificate to Root store.
    exit /b 1
)

certutil -addstore TrustedPublisher "%CERT%" >nul
if errorlevel 1 (
    echo [drvdetect] failed to add certificate to TrustedPublisher store.
    exit /b 1
)

echo [drvdetect] stopping %SERVICE% if it is running...
sc stop "%SERVICE%" >nul 2>&1

echo [drvdetect] pointing %SERVICE% to %DRIVER%...
sc config "%SERVICE%" binPath= "%DRIVER%" >nul
if errorlevel 1 (
    echo [drvdetect] failed to update service path.
    exit /b 1
)

echo [drvdetect] starting %SERVICE%...
sc start "%SERVICE%"
if errorlevel 1 (
    echo [drvdetect] failed to start service.
    exit /b 1
)

echo [drvdetect] launching monitor...
start "" "%MONITOR%"

echo [drvdetect] ready.
exit /b 0
