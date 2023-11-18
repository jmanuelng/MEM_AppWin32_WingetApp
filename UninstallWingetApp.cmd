@echo off
REM Uninstallation script for Install_WingetApp.ps1 using Microsoft Intune Win32 apps

REM Declare the Winget AppID variable. 
REM IMPORTANT: Replace 'YourAppID' with the actual AppID of the Winget application you want to uninstall.
REM Example: SET WingetAppID=Microsoft.VisualStudioCode
SET WingetAppID=YourAppID

REM Set the path to the PowerShell script. It assumes the script is in the current directory.
REM If the script is in a different directory, provide the full path.
REM Example: SET PowerShellScriptPath=C:\Scripts\Install_WingetApp.ps1
SET PowerShellScriptPath=.\Install_WingetApp.ps1

REM Execute the PowerShell script with the specified Winget AppID for uninstallation.
REM Using Sysnative to access the 64-bit version of PowerShell from a 32-bit application.
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "%PowerShellScriptPath%" -WingetAppID "%WingetAppID%" -Uninstall

REM Check for errors in script execution and exit with the error code if an error occurred.
IF %ERRORLEVEL% NEQ 0 (
    echo Uninstallation of %WingetAppID% failed with error code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

REM If no errors occurred, print a success message and exit with code 0.
echo Uninstallation of %WingetAppID% completed successfully.
exit /b 0
