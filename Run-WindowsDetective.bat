@echo off
REM ==========================================================================
REM  Windows Detective launcher - Powered by Bashar Salmo
REM  Double-click (or run from an elevated prompt). Extra arguments are passed
REM  through, e.g.  Run-WindowsDetective.bat -Deep -CollectRawArtifacts
REM ==========================================================================
setlocal
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% equ 0 goto run
echo [*] Requesting administrator rights...
if "%~1"=="" (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
) else (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
)
exit /b
:run
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsDetective.ps1" -OpenReport %*
echo.
pause
endlocal
