# MEM_AppWin32_WingetApp

MEM_AppWin32_WingetApp repository, [https://github.com/jmanuelng/MEM_AppWin32_WingetApp](https://github.com/jmanuelng/MEM_AppWin32_WingetApp). 

This repository contains PowerShell and CMD scripts to deploy Winget applications using Microsoft Intune as Win32 apps. It has been primarily developed and used to deploy applications in a SYSTEM context, although user context deployment is theoretically supported but not extensively tested.

### Repository Contents
- [Detect_WingetApp.ps1](https://raw.githubusercontent.com/jmanuelng/MEM_AppWin32_WingetApp/main/Detect_WingetApp.ps1): Detection script for the Winget application.
- [Install_WingetApp.ps1](https://raw.githubusercontent.com/jmanuelng/MEM_AppWin32_WingetApp/main/Install_WingetApp.ps1): Script for installing or uninstalling Winget applications.
- [W32Winget.cmd](https://github.com/jmanuelng/MEM_AppWin32_WingetApp/blob/main/W32Winget.cmd): CMD script to facilitate the installation and uninstallation process.

## Usage

### Quick Start
For those familiar with Microsoft Intune and PowerShell/CMD scripting:
1. **Download Scripts**: Clone or download the scripts from the repository.
2. **Modify Scripts**: Update `W32Winget.cmd` and `Detect_WingetApp.ps1` with the specific Winget App ID you intend to deploy.
3. **Convert to .intunewin**: Use the Microsoft Intune Win32 App Packaging Tool to convert the modified scripts into the `.intunewin` format.
4. **Deploy via Microsoft Intune**: Upload the `.intunewin` package to Microsoft Intune and configure the deployment settings.

### Detailed Instructions
1. **Downloading the Scripts**:
   - Navigate to the repository and download the required scripts.
   - Ensure you have the latest versions of the scripts.

2. **Modifying the Scripts**:
   - Open `W32Winget.cmd` and `Detect_WingetApp.ps1` in a text editor.
   - Locate the `WingetAppID` variable and replace the placeholder with the actual ID of the application you wish to deploy.

3. **Converting Scripts to .intunewin**:
   - Use the [Microsoft Intune Win32 App Packaging Tool](https://docs.microsoft.com/en-us/mem/intune/apps/apps-win32-app-management) to convert the scripts into the `.intunewin` format.
   - Follow the tool's instructions for packaging.

4. **Deploying via Microsoft Intune**:
   - Log into the Microsoft Intune portal.
   - Navigate to the 'Apps' section and choose to add a new app.
   - Select 'Windows app (Win32)' and upload the `.intunewin` file created using the Microsoft Intune Win32 App Packaging Tool. This package should contain the modified `W32Winget.cmd` (by the way you can change the name of the .CMD, but before creating he .intunewin).
   - Configure the app information, program settings, detection rules, and assignments as per your deployment requirements.
      -  **Install Command**: `W32Winget.cmd install`
      -  **Uninstall Command**: `W32Winget.cmd uninstall`
      -  **Install Behavior**: Set this to 'System'
      -  **Detection Rules**: `Detect_WingetApp.ps1`
      -  **Assignments**: Assign the app to the desired user or devices group(s), as per your organization's needs.
   - For the most up-to-date instructions on deploying Win32 apps, refer to the [official Microsoft documentation](https://docs.microsoft.com/en-us/mem/intune/apps/apps-win32-app-management).
  



### About the scripts

#### Detect_WingetApp.ps1
This script checks if the specified Winget application is installed on the system. It queries the Winget tool for the specified application ID and returns an exit code based on the presence of the application. This script is crucial for Intune to determine the installation state of the application.

#### Install_WingetApp.ps1
This script handles the installation or uninstallation of the specified Winget application. It uses the Winget CLI tool to perform these actions. The script is designed to run in a SYSTEM context for broader compatibility and security considerations. The choice of PowerShell scripting allows for robust error handling and easy integration with Intune's deployment capabilities.

#### W32Winget.cmd
`W32Winget.cmd` serves as a wrapper for `Install_WingetApp.ps1`, simplifying the process of passing parameters like the application ID. It ensures compatibility with Intune's requirements for CMD scripts and provides a straightforward way to execute PowerShell scripts in a Win32 app deployment scenario.

