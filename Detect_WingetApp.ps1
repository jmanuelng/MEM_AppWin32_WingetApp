<#
.SYNOPSIS
    Detects the installation status and version of an application managed by Windows Package Manager (winget) for Microsoft Intune Win32 app deployment.

.DESCRIPTION
    This script is designed to be used as a detection method in Microsoft Intune for Win32 application deployments. It leverages the Windows Package Manager (winget) to check if a specified application is installed, determines if it is the latest version available, and retrieves the installed version details. The script ensures that the necessary dependencies for winget are present and verifies internet connectivity to essential resources required for winget operations.

    It is structured into three main functions:
    - Get-WingetAppDetails: Retrieves the installation status and version of the application.
    - Test-WingetAndDependencies: Checks for the presence of winget and its dependencies.
    - Test-InternetConnectivity: Ensures connectivity to resources needed by winget.

    The script outputs a detailed summary of the detection process and exits with a status code that can be used to inform Intune deployment workflows.

.PARAMETER WingetAppID
    NOT USED, that was the idea. Win32 Detect script does not take parameters.
    ....The application identifier for the Windows Package Manager (winget) to check the application.

.EXAMPLE
    .\Detect_WingetApp.ps1 
    $WingetAppID = "Microsoft.VisualStudioCode"
    Checks if Visual Studio Code is installed, verifies the version, and outputs the detection summary.

.NOTES
    This script is intended for use with Microsoft Intune and assumes that winget is installed and operational on the target system. It should be thoroughly tested in a non-production environment before being deployed.


.LAST MODIFIED
    Nove 9th, 2023

#>



#region Functions

function Invoke-Ensure64bitEnvironment {
    <#
    .SYNOPSIS
        Check if the script is running in a 32-bit or 64-bit environment, and relaunch using 64-bit PowerShell if necessary.

    .NOTES
        This script checks the processor architecture to determine the environment.
        If it's running in a 32-bit environment on a 64-bit system (WOW64), 
        it will relaunch using the 64-bit version of PowerShell.
        Place the function at the beginning of the script to ensure a switch to 64-bit when necessary.
    #>
    if ($ENV:PROCESSOR_ARCHITECTURE -eq "x86" -and $ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
        Write-Output "Detected 32-bit PowerShell on 64-bit system. Relaunching script in 64-bit environment..."
        Start-Process -FilePath "$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-WindowStyle Hidden -NonInteractive -File `"$($PSCommandPath)`" " -Wait -NoNewWindow
        exit # Terminate the 32-bit process
    } elseif ($ENV:PROCESSOR_ARCHITECTURE -eq "x86") {
        Write-Output "Detected 32-bit PowerShell on a 32-bit system. Stopping script execution."
        exit # Terminate the script if it's a pure 32-bit system
    }
}

function Find-WingetPath {
    <#
    .SYNOPSIS
        Locates and verifies the accessibility of the winget.exe executable within a Windows system.

    .DESCRIPTION
        This function is designed to find the path of the `winget.exe` executable on a Windows system 
         and ensure it is accessible for execution. 
        Used for scripts that need to interact with the Windows Package Manager (winget) 
         in environments where the script may be running under different user contexts, including SYSTEM and USER.

        The Windows Package Manager (winget) is a command-line utility that simplifies the installation,
         upgrade, configuration, and removal of software packages. Accurately locating `winget.exe` and
         verifying its accessibility have probed to be crucail for enabling automated software management tasks, 
         especially when executed under the SYSTEM context.

        Methodology:
        1. Defining Potential Paths:
        - The function defines a list of potential file paths where `winget.exe` might be located. 
          These paths include:
            - The standard Program Files directory, typically used on 64-bit systems.
            - The 32-bit Program Files directory, for 32-bit applications on 64-bit systems.
            - The Local Application Data directory.
            - The Current User's Local Application Data directory.
        - These paths may contain wildcards (*) to accommodate flexible directory naming, such as version-specific folder names.

        2. Iterating Through Paths and Verifying Accessibility:
            - The function iterates over each potential location, resolving any paths with wildcards to their actual directories.
            - For each resolved path, it uses `Get-ChildItem` to search for `winget.exe`.
            - Upon locating `winget.exe`, the function checks if the current context has execution permissions for the file.
            - If necessary, it attempts to modify the file's Access Control List (ACL) to grant execute permissions.
            - This step ensures that the located `winget.exe` is not only present but also executable by the script.

        3. Returning Results:
            - If `winget.exe` is found and is accessible, the function returns the full path to the executable.
            - If `winget.exe` is not found or cannot be made accessible, it outputs an error message and returns `$null`.

    .EXAMPLE
        $wingetLocation = Find-WingetPath
        if ($wingetLocation) {
            Write-Output "Winget found and accessible at: $wingetLocation"
        } else {
            Write-Error "Winget was not found or is not accessible on this system."
        }

    .NOTES
 
    .DISCLAIMER
        This function is provided 'as-is' with no warranties or guarantees. It should be thoroughly tested in a controlled environment before any production use. The design and robustness of this function have been enhanced with the assistance of ChatGPT. However, as with all automated tools and scripts, it is essential to review and test them within their specific application context.

    #>

    # Define potential locations for winget.exe
    # These locations are the most common paths where winget.exe might be installed.
    $possibleLocations = @(
        "${env:ProgramFiles}\WindowsApps\Microsoft.DesktopAppInstaller*_x64__8wekyb3d8bbwe\winget.exe", 
        "${env:ProgramFiles(x86)}\WindowsApps\Microsoft.DesktopAppInstaller*_8wekyb3d8bbwe\winget.exe",
        "${env:LOCALAPPDATA}\Microsoft\WindowsApps\winget.exe",
        "${env:USERPROFILE}\AppData\Local\Microsoft\WindowsApps\winget.exe"
    )

    # Function to check and modify permissions
    # This function attempts to add execute permissions to the winget.exe file.
    function CheckAndModifyPermissions {
        param (
            [string]$filePath
        )
        try {
            Write-Host "Verifying execution permissions for $filePath"
            # Get the current Access Control List (ACL) of the file
            $acl = Get-Acl $filePath
            # Define the execution permission
            $executionPermission = [System.Security.AccessControl.FileSystemRights]::Execute
    
            # Get the current user's account
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $currentUserAccount = New-Object System.Security.Principal.NTAccount($currentUser)
    
            # Check if the current user already has execute permissions
            $accessRules = $acl.Access | Where-Object { $_.IdentityReference -eq $currentUserAccount }
            $hasExecutePermission = $accessRules | Where-Object { $_.FileSystemRights -match 'Execute' -or $_.FileSystemRights -match 'FullControl' }
    
            if ($hasExecutePermission) {
                Write-Host "$currentUser already has execute permissions."
                return $true
            }
    
            # If the current user does not have the necessary permissions, attempt to modify the ACL
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUserAccount, $executionPermission, 'Allow')
            $acl.AddAccessRule($accessRule)
            Set-Acl -Path $filePath -AclObject $acl
            return $true
        }
        catch {
            Write-Warning "Failed to modify permissions for: $filePath"
            return $false
        }
    }
       

    # Iterate through potential locations to find and verify winget.exe
    # This loop checks each location in the list for the presence of winget.exe.
    foreach ($location in $possibleLocations) {
        try {
            # Check if the location contains a wildcard and resolve it
            if ($location -like '*`**') {
                # Resolve the wildcard path to actual directory paths
                $resolvedPaths = Resolve-Path $location -ErrorAction SilentlyContinue
                # Update the location with the resolved path if available
                if ($resolvedPaths) {
                    $location = $resolvedPaths.Path
                }
                else {
                    # If path couldn't be resolved, inform via write warning
                    Write-Warning "Couldn't resolve path for: $location"
                    # Skip to the next location if the path cannot be resolved
                    continue
                }
            }

            # Search for winget.exe in the resolved location
            # Get-ChildItem is used to find the winget.exe file in the specified directory.
            $items = Get-ChildItem -Path $location -ErrorAction Stop
            # Iterate through each found item to check and modify permissions
            if ($items -and $items.Count -gt 0) {
                # Found a path, saving to variable and informing
                $wingetPath = $items[0].FullName
                Write-Host "Found Winget at: $wingetPath"
                # Check and modify permissions if necessary
                $hasPermission = CheckAndModifyPermissions -filePath $wingetPath
                # If the file is accessible, return its path
                if ($hasPermission) {
                    Write-Host "Winget found and accessible at: $wingetPath"
                    return $wingetPath
                } else {
                    Write-Host "Unable to confirm Winget execution permissions."
                }
            }
        }
        catch {
            # Catch any exceptions during the search and output a warning
            Write-Warning "Couldn't search for winget.exe at: $location"
        }
    }

    # If winget.exe is not found in any of the locations, output an error
    Write-Error "Winget wasn't located or accessible in any of the specified locations."
    return $null
}

function Get-WingetAppDetails {
    <#
    .SYNOPSIS
        Retrieves details about an application's installation status and version using Windows Package Manager (winget).

    .DESCRIPTION
        This function checks if a specified application is installed on the system, determines if the installed version is the latest available version, and retrieves the specific installed version number. It utilizes the 'winget' command-line tool to query the local package repository.

    .PARAMETER AppID
        The application identifier (ID) for the application to check, as recognized by winget.

    .PARAMETER WingetPath
        Optional parameter to specify a complete path to the winget executable.

    .EXAMPLE
        $appDetails = Get-WingetAppDetails -AppID "Microsoft.VisualStudioCode"
        This command will check if Visual Studio Code is installed, if it's the latest version, and what the installed version is.

    .OUTPUTS
        PSCustomObject with the following properties:
        - IsInstalled: [bool] Indicates if the application is installed.
        - IsLatestVersion: [bool] Indicates if the installed version is the latest.
        - InstalledVersion: [string] The version number of the installed application.

    .NOTES
        Requires Windows Package Manager (winget) to be installed and accessible in the system PATH.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$AppID,

        [string]$WingetPath
    )

    # Initialize the result object with default values
    $result = New-Object PSObject -Property @{
        IsInstalled = $false
        IsLatestVersion = $false
        InstalledVersion = $null
    }

    try {
        # If WingetPath is not provided, attempt to locate winget automatically
        if (-not $WingetPath) {
            $WingetPath = (Get-Command 'winget').Source
        }

        # Query the installed application using winget and clean up the output
        $installedApp = & $wingetPath list --id $AppID -e | Out-String

        # Remove non-alphanumeric characters (except for periods, hyphens, and new lines) from the output
        $cleanOutput = $installedApp -replace '[^\w.\-\r\n]', ' ' -replace '\s+', ' ' -replace '^\s+|\s+$', ''

        # Split the output into lines and remove empty lines
        $outputLines = ($cleanOutput -split '\r?\n').Trim() | Where-Object { $_ -ne '' }

        # Find the line with the application details using regex to match the version number pattern
        $appDetailsLine = $outputLines | Where-Object { $_ -match "$AppID\s+(\d+(\.\d+)+)" }

        if ($appDetailsLine) {
            $result.IsInstalled = $true

            # Extract the version number using the regex match
            $matches = [regex]::Matches($appDetailsLine, "$AppID\s+(\d+(\.\d+)+)")
            $result.InstalledVersion = $matches[0].Groups[1].Value

            if ($result.IsInstalled) {
                # Use winget search to find the latest version available in the repository
                $latestApp = & $wingetPath search --id $AppID -e | Out-String
                # Clean up the output for the latest version
                $latestCleanOutput = $latestApp -replace '[^\w.\-\r\n]', ' ' -replace '\s+', ' ' -replace '^\s+|\s+$', ''
                $latestOutputLines = ($latestCleanOutput -split '\r?\n').Trim() | Where-Object { $_ -ne '' }
                $latestVersionLine = $latestOutputLines | Where-Object { $_ -match "$AppID\s+(\d+(\.\d+)+)" }
    
                if ($latestVersionLine) {
                    # Extract the latest version number using regex
                    $latestMatches = [regex]::Matches($latestVersionLine, "$AppID\s+(\d+(\.\d+)+)")
                    $latestVersion = $latestMatches[0].Groups[1].Value
    
                    # Check if the installed version matches the latest available version
                    if ($result.InstalledVersion -eq $latestVersion) {
                        $result.IsLatestVersion = $true
                    }
                }
            }
        }
    }
    catch {
        Write-Error "Error occurred while attempting to retrieve application details: $_"
    }

    return $result
}

function Test-WingetAndDependencies {
    <#
    .SYNOPSIS
    Tests for the presence of Winget and required dependencies on the system.

    .DESCRIPTION
    Checks if the Windows Package Manager (Winget) is installed and verifies necessary dependencies, 
    including the Desktop App Installer, Microsoft.UI.Xaml, and the Visual C++ Redistributable. 
    Returns a string with unique identifiers indicating the result of the check and outputs feedback to the console.
    This allows for precise identification of which components are missing.

    .EXAMPLE
    $checkResult = Test-WingetAndDependencies
    if ($checkResult -eq "0") {
        Write-Host "Winget and all dependencies are present."
    } else {
        Write-Host "Missing components: $checkResult"
    }
    This example calls the Test-WingetAndDependencies function and acts based on the returned status string.

    .OUTPUTS
    String
    Returns a string value with concatenated identifiers indicating the status of the check:
    "0" - Winget and all dependencies are detected successfully.
    "W" - Winget is not detected.
    "D" - Desktop App Installer is not detected.
    "U" - Microsoft.UI.Xaml is not detected.
    "V" - Visual C++ Redistributable is not detected.
    Concatenated string for multiple missing components, e.g., "DU" for missing Desktop App Installer and Microsoft.UI.Xaml.

    .NOTES
    Date: November 9, 2023
    The function does not attempt to install Winget or its dependencies. It only checks for their presence, reports the findings, and outputs feedback to the console.

    .LINK
    Documentation for Winget: https://docs.microsoft.com/en-us/windows/package-manager/winget/
    #>

    # Initialize an array to hold missing component identifiers
    $missingComponents = @()

    # Check if Winget is installed
    $wingetPath = (Get-Command -Name winget -ErrorAction SilentlyContinue).Source
    if (-not $wingetPath) {
        $missingComponents += "W" # Add 'W' to the array if Winget is missing
        Write-Host "Winget is NOT installed."
    } else {
        Write-Host "Winget is installed."
    }

    # Check for Desktop App Installer
    $desktopAppInstaller = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue
    if (-not $desktopAppInstaller) {
        $missingComponents += "D" # Add 'D' to the array if Desktop App Installer is missing
        Write-Host "Desktop App Installer is NOT installed."
    } else {
        Write-Host "Desktop App Installer is installed."
    }

    # Check for Microsoft.UI.Xaml
    $uiXaml = Get-AppxPackage -Name Microsoft.UI.Xaml.2* -ErrorAction SilentlyContinue # Assuming version 2.x is required
    if (-not $uiXaml) {
        $missingComponents += "U" # Add 'U' to the array if Microsoft.UI.Xaml is missing
        Write-Host "Microsoft.UI.Xaml is NOT installed."
    } else {
        Write-Host "Microsoft.UI.Xaml is installed."
    }

    # Check for Visual C++ Redistributable
    $vcDisplayName = "Microsoft Visual C++ 2015-2022 Redistributable (x64)"
    $vcInstalled = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall, 
                                  HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
                   Get-ItemProperty |
                   Where-Object { $_.DisplayName -like "*$vcDisplayName*" } -ErrorAction SilentlyContinue
    if (-not $vcInstalled) {
        $missingComponents += "V" # Add 'V' to the array if Visual C++ Redistributable is missing
        Write-Host "Visual C++ Redistributable is NOT installed."
    } else {
        Write-Host "Visual C++ Redistributable is installed."
    }

    # Return a concatenated string of missing component identifiers
    # If no components are missing, return '0'
    if ($missingComponents.Length -eq 0) {
        return "0"
    } else {
        return [String]::Join('', $missingComponents)
    }
}

function Test-InternetConnectivity {
    <#
    .SYNOPSIS
    Confirms internet connectivity to download content from github.com and nuget.org.

    .DESCRIPTION
    Tests the TCP connection to github.com and nuget.org on port 443 (HTTPS) to confirm internet connectivity.
    Returns a string of characters that clearly identifies if there is a connectivity issue, and if so, to which URL or site.
    Additionally, outputs simplified but clear feedback to the console.

    .EXAMPLE
    Test-InternetConnectivity
    This example calls the Test-InternetConnectivity function and outputs the result to the console.

    .OUTPUTS
    String
    Returns a string of characters indicating the connectivity status:
    '0' - No connectivity issues.
    'G' - Connectivity issue with github.com.
    'N' - Connectivity issue with nuget.org.
    'GN' - Connectivity issues with both sites.

    .NOTES
    Date: November 2, 2023
    #>

    # Initialize a variable to hold the connectivity status
    $connectivityStatus = ''

    # Test connectivity to github.com
    $githubTest = Test-NetConnection -ComputerName 'github.com' -Port 443 -ErrorAction SilentlyContinue
    if (-not $githubTest.TcpTestSucceeded) {
        $connectivityStatus += 'G'
        Write-Host "Connectivity issue with github.com."
    } else {
        Write-Host "Successfully connected to github.com."
    }

    # Test connectivity to nuget.org
    $nugetTest = Test-NetConnection -ComputerName 'nuget.org' -Port 443 -ErrorAction SilentlyContinue
    if (-not $nugetTest.TcpTestSucceeded) {
        $connectivityStatus += 'N'
        Write-Host "Connectivity issue with nuget.org."
    } else {
        Write-Host "Successfully connected to nuget.org."
    }

    # Determine the return value based on the tests
    if ($connectivityStatus -eq '') {
        Write-Host "Internet connectivity to both github.com and nuget.org is confirmed."
        return '0' # No issues
    } else {
        Write-Host "Connectivity test completed with issues: $connectivityStatus"
        return $connectivityStatus # Return the specific issue(s)
    }
}

#endregion Functions

#region Main

#region Variables
$WingetAppID = "Your.AppID"     # Winget Application ID. 
                                #  $WingetAppID HAS to be manually updated, Win32 detect script does not accept parameters.
$appWinget = $null              # Stores App details
$WingetAppVer = $null           # For App version
$WingetAppIsLatest = $null        # To confirm that latest version is Installed
$detectSummary = ""             # Summary of script execution
$result = 0                     # Script execution result
#endregion Variables

# Clear errors
$Error.Clear()

# Make the log easier to read
Write-Host `n`n

# Invoke the function to ensure we're running in a 64-bit environment if available
Invoke-Ensure64bitEnvironment
Write-Host "Script running in 64-bit environment."

$wingetPath = Find-WingetPath

# Check if Winget Application is installed
$appWinget = Get-WingetAppDetails -AppID $WingetAppID -WingetPath $wingetPath

# Some spaces to make it easier to read in log file
Write-Host `n`n

if ($appWinget.IsInstalled) {
    # Get the current version of he Winget Application
    $WingetAppVer = $appWinget.InstalledVersion
    $WingetAppIsLatest = $appWinget.IsLatestVersion
    Write-Host "Found $WingetAppID version $WingetAppVer."
    $detectSummary += "App $WingetAppID version $WingetAppVer. " 
    if (-not $WingetAppIsLatest) {
        Write-Host "There is a newer $WingetAppID version available."
        $detectSummary += "Newer $WingetAppID version available. " 
    } else {
        Write-Host "It is newest available version for $WingetAppID."
    }
}
else {
    Write-Host "$WingetAppID not installed on device."
    $detectSummary += "$WingetAppID not found on device. "

    # If Winget Application not installed, check Winget and dependencies
    $wingetCheckResult = Test-WingetAndDependencies
    # Adjust the switch to handle string identifiers
    switch -Regex ($wingetCheckResult) {
        '0' { 
            $detectSummary = "Winget and all dependencies detected successfully. " # Set summary exclusively for this case
            break # Exit the switch to avoid processing other cases
        }
        'W' { $detectSummary += "Winget NOT detected. " }
        'D' { $detectSummary += "Desktop App Installer NOT detected. " }
        'U' { $detectSummary += "Microsoft.UI.Xaml NOT detected. " }
        'V' { $detectSummary += "Visual C++ Redistributable NOT detected. " }
        Default { $detectSummary += "Unknown dependency check result: $wingetCheckResult " }
    }

    # Check internet connectivity to github.com and nuget.org
    $internetConnectivityResult = Test-InternetConnectivity
    # Adjust the switch to handle string identifiers for connectivity results
    switch -Regex ($internetConnectivityResult) {
        '0' { 
            $detectSummary += "Connectivity to github.com and nuget.org confirmed. "
        }
        'G' { $detectSummary += "Connectivity issue with github.com. " }
        'N' { $detectSummary += "Connectivity issue with nuget.org. " }
        'GN' { $detectSummary += "Connectivity issues with both github.com and nuget.org. " }
        Default { $detectSummary += "Unknown connectivity check result: $internetConnectivityResult " }
    }
    
    $result = 1
}

# Some spaces to make it easier to read in log file
Write-Host `n`n


#Return result
if ($result -eq 0) {
    Write-Host "OK $([datetime]::Now) : $detectSummary"
    Exit 0
}
elseif ($result -eq 1) {
    Write-Host "FAIL $([datetime]::Now) : $detectSummary"
    Exit 1
}
else {
    Write-Host "NOTE $([datetime]::Now) : $detectSummary"
    Exit 0
}
