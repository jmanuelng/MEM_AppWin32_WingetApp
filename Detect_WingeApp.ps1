
#region Functions

function Get-WingetAppDetails {
    <#
    .SYNOPSIS
        Retrieves details about an application's installation status and version using Windows Package Manager (winget).

    .DESCRIPTION
        This function checks if a specified application is installed on the system, determines if the installed version is the latest available version, and retrieves the specific installed version number. It utilizes the 'winget' command-line tool to query the local package repository.

    .PARAMETER AppID
        The application identifier (ID) for the application to check, as recognized by winget.

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
        [string]$AppID
    )

    # Initialize the result object with default values
    $result = New-Object PSObject -Property @{
        IsInstalled = $false
        IsLatestVersion = $false
        InstalledVersion = $null
    }

    try {
        # Validate that winget is installed and accessible
        $wingetPath = Get-Command 'winget' -ErrorAction Stop

        # Query the installed application using winget
        $installedApp = & $wingetPath list --id $AppID -e | Out-String

        # Check if the application is installed by looking for the AppID in the output
        if ($installedApp -match $AppID) {
            $result.IsInstalled = $true

            # Parse the output to extract the installed version number
            $installedVersion = ($installedApp -split '\r?\n' | Where-Object { $_ -match $AppID }) -split '\s+', 3 | Select-Object -Last 1
            $result.InstalledVersion = $installedVersion.Trim()

            # Query the latest available version of the application using winget
            $latestApp = & $wingetPath show --id $AppID -e | Out-String
            $latestVersion = ($latestApp -split '\r?\n' | Where-Object { $_ -match 'Available' }) -split '\s+', 3 | Select-Object -Last 1

            # Check if the installed version matches the latest available version
            if ($installedVersion -eq $latestVersion.Trim()) {
                $result.IsLatestVersion = $true
            }
        }
    }
    catch {
        # Advanced error handling to capture and report any exceptions
        Write-Error "An error occurred while attempting to retrieve application details: $_"
    }

    # Return the result object
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
$WingetAppVer = $null              # For App version
$detectSummary = ""             # Summary of script execution
$result = 0                     # Script execution result
#endregion Variables

# Clear errors
$Error.Clear()

# Check if Winget Application is installed
$appWinget = Get-WingetAppDetails

# Some spaces to make it easier to read in log file
Write-Host `n`n

if ($null -ne $appWinget) {
    # Get the current version of he Winget Application
    $WingetAppVer = $appWinget.InstalledVersion
    Write-Host "Found Application $WingetAppID version $WingetAppVer"
    $detectSummary += "App $WingetAppID version = $WingetAppVer. " 
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
