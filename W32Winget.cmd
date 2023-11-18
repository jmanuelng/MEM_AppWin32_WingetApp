@echo off
REM Combined script for installing or uninstalling WinGet applications using Microsoft Intune Win32 apps
REM 
REM Instructions:
REM 1. Replace 'YourAppID' with the actual AppID of the WinGet application you want to install or uninstall.
REM    Example: SET WingetAppID=Microsoft.VisualStudioCode
REM 2. Run this script with 'install' or 'uninstall' as an argument. If no argument is provided, it defaults to 'install'.
REM    Example: W32WingetApp.cmd install
REM    Example: W32WingetApp.cmd uninstall
REM 
REM The WingetAppID is set at the top for easy access and modification.

SET WingetAppID=YourAppID

REM Set the path to the PowerShell script. Assumes the script is in the current directory.
REM Example: SET PowerShellScriptPath=C:\Scripts\Install_WingetApp.ps1
SET PowerShellScriptPath=.\Install_WingetApp.ps1

REM Check for command line argument (install or uninstall)
IF "%1"=="" GOTO Install
IF /I "%1"=="install" GOTO Install
IF /I "%1"=="uninstall" GOTO Uninstall
GOTO InvalidArgument

:Install
REM Execute the PowerShell script for installation.
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "%PowerShellScriptPath%" -WingetAppID "%WingetAppID%"

REM Check for errors and exit with the error code if an error occurred.
IF %ERRORLEVEL% NEQ 0 (
    echo Installation of %WingetAppID% failed with error code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

REM Success message for installation.
echo Installation of %WingetAppID% completed successfully.
exit /b 0

:Uninstall
REM Execute the PowerShell script for uninstallation.
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "%PowerShellScriptPath%" -WingetAppID "%WingetAppID%" -Uninstall

REM Check for errors and exit with the error code if an error occurred.
IF %ERRORLEVEL% NEQ 0 (
    echo Uninstallation of %WingetAppID% failed with error code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

REM Success message for uninstallation.
echo Uninstallation of %WingetAppID% completed successfully.
exit /b 0

:InvalidArgument
echo Invalid argument. Please use 'install' or 'uninstall'.
exit /b 1
