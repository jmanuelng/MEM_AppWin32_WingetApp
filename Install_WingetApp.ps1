<#
.SYNOPSIS
    Script installs or uninstalls specified application using the Windows Package Manager (winget) based on a mandatory parameter "WingetAppID".

.DESCRIPTION
    The script requires a mandatory parameter "WingetAppID" which is the application identifier for winget.
    It includes a function to capture important information about the application and ensures that the environment is suitable for installation or uninstallation.
    While the script is generally effective with most applications, it is imperative to perform extensive testing prior to deployment. 
        For instance, issues were encountered when silently uninstalling certain applications, such as Citrix Workspace. 
        Solutions and community discussions, such as the one found at https://www.reddit.com/r/sysadmin/comments/144jle7/winget_silent_uninstall_citrixworkspace/, 
        can provide valuable insights for handling such exceptions.
    The script was designed to be distributed via Win32App using Intune.

.PARAMETER WingetAppID
    The application identifier for the Windows Package Manager (winget) to install or uninstall the application.

.PARAMETER Uninstall
    Indicates that the script should uninstall the application, rather than install it.

.EXAMPLE
    .\Install_WingetApp.ps1 -WingetAppID "Your.ApplicationID"
    Installs the application associated with "Your.ApplicationID" using Winget, assuming Winget is available on the device.

.EXAMPLE
    .\Install_WingetApp.ps1 -WingetAppID "Microsoft.Teams" -Uninstall
    This example uninstalls the Microsoft Teams application without user interaction, using the silent uninstall feature of Winget.

.NOTES
    This script is provided as-is without any guarantees or warranties. Always ensure you have backups and take necessary precautions when executing scripts, particularly in production environments. Due to the varying nature of application installers, some applications may not uninstall silently as expected. It is recommended to test the script thoroughly with each application, especially those known to have complex uninstallation routines.

.LAST MODIFIED
    November 9th, 2023

#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$WingetAppID,

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall
)

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
        Locates the winget.exe executable within a system.

    .DESCRIPTION
        Finds the path of the `winget.exe` executable on a Windows system. 
        Aimed at finding Winget when main script is executed as SYSTEM, but will also work under USER
        
        Windows Package Manager (`winget`) is a command-line tool that facilitates the 
        installation, upgrade, configuration, and removal of software packages. Identifying the 
        exact path of `winget.exe` allows for execution (installations) under SYSTEM context.

        METHOD
        1. Defining Potential Paths:
        - Specifies potential locations of `winget.exe`, considering:
            - Standard Program Files directory (64-bit systems).
            - 32-bit Program Files directory (32-bit applications on 64-bit systems).
            - Local application data directory.
            - Current user's local application data directory.
        - Paths may utilize wildcards (*) for flexible directory naming, e.g., version-specific folder names.

        2. Iterating Through Paths:
        - Iterates over each potential location.
        - Resolves paths containing wildcards to their actual path using `Resolve-Path`.
        - For each valid location, uses `Get-ChildItem` to search for `winget.exe`.

        3. Returning Results:
        - If `winget.exe` is located, returns the full path to the executable.
        - If not found in any location, outputs an error message and returns `$null`.

    .EXAMPLE
        $wingetLocation = Find-WingetPath
        if ($wingetLocation) {
            Write-Output "Winget found at: $wingetLocation"
        } else {
            Write-Error "Winget was not found on this system."
        }

    .NOTES
        While this function is designed for robustness, it relies on current naming conventions and
        structures used by the Windows Package Manager's installation. Future software updates may
        necessitate adjustments to this function.

    .DISCLAIMER
        This function and script is provided as-is with no warranties or guarantees of any kind. 
        Always test scripts and tools in a controlled environment before deploying them in a production setting.
        
        This function's design and robustness were enhanced with the assistance of ChatGPT, it's important to recognize that 
        its guidance, like all automated tools, should be reviewed and tested within the specific context it's being 
        applied. 

    #>
    # Define possible locations for winget.exe
    $possibleLocations = @(
        "${env:ProgramFiles}\WindowsApps\Microsoft.DesktopAppInstaller*_x64__8wekyb3d8bbwe\winget.exe", 
        "${env:ProgramFiles(x86)}\WindowsApps\Microsoft.DesktopAppInstaller*_8wekyb3d8bbwe\winget.exe",
        "${env:LOCALAPPDATA}\Microsoft\WindowsApps\winget.exe",
        "${env:USERPROFILE}\AppData\Local\Microsoft\WindowsApps\winget.exe"
    )

    # Iterate through the potential locations and return the path if found
    foreach ($location in $possibleLocations) {
        try {
            # Resolve path if it contains a wildcard
            if ($location -like '*`**') {
                $resolvedPaths = Resolve-Path $location -ErrorAction SilentlyContinue
                # If the path is resolved, update the location for Get-ChildItem
                if ($resolvedPaths) {
                    $location = $resolvedPaths.Path
                }
                else {
                    # If path couldn't be resolved, skip to the next iteration
                    Write-Warning "Couldn't resolve path for: $location"
                    continue
                }
            }
            
            # Try to find winget.exe using Get-ChildItem
            $items = Get-ChildItem -Path $location -ErrorAction Stop
            if ($items -and $items.Count -gt 0) {
                $wingetPath = $items[0].FullName
                Write-Host "Found Winget at: $wingetPath"
                return $wingetPath
            } else {
                Write-Host "Winget not found in location: $location"
            }
        }
        catch {
            Write-Warning "Couldn't search for winget.exe at: $location"
        }
    }

    Write-Error "Winget wasn't located in any of the specified locations."
    return $null
}

function Install-VisualCIfMissing {
    <#
    .SYNOPSIS
        Checks for the presence of Microsoft Visual C++ Redistributable on the system and installs it if missing.

    .DESCRIPTION
        This function is designed to ensure that the Microsoft Visual C++ 2015-2022 Redistributable (x64) is installed on the system.
        It checks the system's uninstall registry keys for an existing installation of the specified version of Visual C++ Redistributable.
        If not found, proceeds to download the installer from the official Microsoft link and installs it silently without user interaction.
        Function returns a boolean value indicating the success or failure of the installation or the presence of the redistributable.


    .PARAMETER vcRedistUrl
        The URL from which the Visual C++ Redistributable installer will be downloaded.
        Default is set to the latest supported Visual C++ Redistributable direct download link from Microsoft.

    .PARAMETER vcRedistFilePath
        The local file path where the Visual C++ Redistributable installer will be downloaded to.
        Default is set to the Windows TEMP directory with the filename 'vc_redist.x64.exe'.

    .PARAMETER vcDisplayName
        The display name of the Visual C++ Redistributable to check for in the system's uninstall registry keys.
        This is used to determine if the redistributable is already installed.

    .EXAMPLE
        $vcInstalled = Install-VisualCIfMissing
        This example calls the function and stores the result in the variable $vcInstalled.
        After execution, $vcInstalled will be true if the redistributable is installed, otherwise false.

    .NOTES
        This function requires administrative privileges to install the Visual C++ Redistributable.
        Ensure that the script is run in a context that has the necessary permissions.

        The function uses the Start-Process cmdlet to execute the installer, which requires the '-Wait' parameter to ensure
        that the installation process completes before the script proceeds.

        Error handling is implemented to catch any exceptions during the download and installation process.
        If an error occurs, the function will return false and output the error message.

        It is recommended to test this function in a controlled environment before deploying it in a production setting.

    .LINK
        For more information on Microsoft Visual C++ Redistributable, visit:
        https://docs.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist

    #>

    # Define the Visual C++ Redistributable download URL and file path
    $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $vcRedistFilePath = "$env:TEMP\vc_redist.x64.exe"

    # Define the display name for the Visual C++ Redistributable to check if it's installed
    $vcDisplayName = "Microsoft Visual C++ 2015-2022 Redistributable (x64)"

    # Check if Visual C++ Redistributable is already installed
    $vcInstalled = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
                   Get-ItemProperty |
                   Where-Object { $_.DisplayName -like "*$vcDisplayName*" }

    if ($vcInstalled) {
        # Visual C++ is already installed, no action needed
        Write-Host "Microsoft Visual C++ Redistributable is already installed."
        return $true
    } else {
        # Visual C++ is not installed, proceed with download and installation
        Write-Host "Microsoft Visual C++ Redistributable not found. Attempting to install..."

        # Attempt to download the Visual C++ Redistributable installer
        try {
            Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcRedistFilePath -ErrorAction Stop
            Write-Host "Download of Visual C++ Redistributable succeeded."
        } catch {
            # Log detailed error message and halt execution if download fails
            Write-Error "Failed to download Visual C++ Redistributable: $($_.Exception.Message)"
            return $false
        }

        # Attempt to install the Visual C++ Redistributable
        try {
            # Start the installer and wait for it to complete, capturing the process object
            $process = Start-Process -FilePath $vcRedistFilePath -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru -ErrorAction Stop
            # Check the exit code of the installer process to determine success
            if ($process.ExitCode -eq 0) {
                Write-Host "Successfully installed Microsoft Visual C++ Redistributable."
                return $true
            } else {
                # Log detailed error message if installation fails
                Write-Error "Visual C++ Redistributable installation failed with exit code $($process.ExitCode)."
                return $false
            }
        } catch {
            # Log detailed error message and halt execution if installation process fails
            Write-Error "Failed to install Visual C++ Redistributable: $($_.Exception.Message)"
            return $false
        }
    }
                
}


function Get-LoggedOnUser {
    <#
    .SYNOPSIS
    Retrieves the user identifier of the currently logged-on user or the most recently logged-on user based on active explorer.exe processes.

    .DESCRIPTION
    The function performs a two-step verification to determine the active user on a Windows system. 
    Initially, it attempts to identify the currently logged-on user via the Win32_ComputerSystem class. 
    Should this approach fail, it proceeds to evaluate all running explorer.exe processes to ascertain 
    which user session was initiated most recently.

    .OUTPUTS
    System.String
    Outputs a string in the format "DOMAIN\Username" representing the active or most recent user. 
    If no user can be identified, it outputs $null.

    .EXAMPLE
    $UserId = Get-LoggedOnUser
    if ($UserId) {
        Write-Host "The active or most recently connected user is: $UserId"
    } else {
        Write-Host "Unable to identify the active or most recently connected user."
    }

    In this example, the function retrieves the user identifier of the active or most recent user
    and prints it to the console. If no user can be determined, it conveys an appropriate message.

    .NOTES
    Execution context: This function is intended to be run with administrative privileges to ensure accurate retrieval of user information.

    Assumptions: This function assumes that the presence of an explorer.exe process correlates with an interactive user session
     and utilizes this assumption to determine the user identity.

    Error Handling: If the function encounters any issues while attempting to identify the user via Win32_ComputerSystem,
     it outputs a warning and falls back to the process-based identification method.

    #>

    # Initialization and Win32_ComputerSystem user retrieval
    $loggedOnUser = $null
    try {
        $loggedOnUser = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
        if ($loggedOnUser) {
            return $loggedOnUser
        }
    } catch {
        Write-Warning "Query to Win32_ComputerSystem failed to retrieve the logged-on user."
    }

    # Fallback method using explorer.exe processes
    $explorerProcesses = Get-WmiObject Win32_Process -Filter "name = 'explorer.exe'"
    $userSessions = @()
    foreach ($process in $explorerProcesses) {
        $ownerInfo = $process.GetOwner()
        $startTime = $process.ConvertToDateTime($process.CreationDate)
        $userSessions += New-Object PSObject -Property @{
            User      = "$($ownerInfo.Domain)\$($ownerInfo.User)"
            StartTime = $startTime
        }
    }

    # Identification of the most recent user session
    $mostRecentUserSession = $userSessions | Sort-Object StartTime -Descending | Select-Object -First 1
    if ($mostRecentUserSession) {
        return $mostRecentUserSession.User
    } else {
        return $null
    }
}


function Install-WingetAsSystem {
    <#
    .SYNOPSIS
        Installs the Windows Package Manager (winget) as a system app by creating a scheduled task.

    .DESCRIPTION
        This function creates a scheduled task that runs a PowerShell script to install the latest version of winget and its dependencies.
        It is designed to install winget in the system context, making it available to all users on the device.
        The installation script is adapted from the winget-pkgs repository on GitHub, ensuring the latest version and dependencies are installed.

        The function is based on the 'InstallWingetAsSystem' function from the 'Winget-InstallPackage.ps1' script
        by djust270, which can be found at:
        https://github.com/djust270/Intune-Scripts/blob/master/Winget-InstallPackage.ps1

        The installation script within the function is adapted from:
        https://github.com/microsoft/winget-pkgs/blob/master/Tools/SandboxTest.ps1

    .EXAMPLE
        Install-WingetAsSystem

        Installs winget as a system app by creating and running a scheduled task.

    .NOTES
        Administrative privileges are required to create scheduled tasks and install winget as a system app.

    .LINK
        Original script source for Install-WingetAsSystem: https://github.com/djust270/Intune-Scripts/blob/master/Winget-InstallPackage.ps1
        Original script source for winget installation: https://github.com/microsoft/winget-pkgs/blob/master/Tools/SandboxTest.ps1

    #>
    # PowerShell script block that will be executed by the scheduled task
    $scriptBlock = @'
        # Function to install the latest version of WinGet and its dependencies
        function Install-WinGet {
            $tempFolderName = 'WinGetInstall'
            $tempFolder = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $tempFolderName
            New-Item $tempFolder -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            
            $apiLatestUrl = if ($Prerelease) { 'https://api.github.com/repos/microsoft/winget-cli/releases?per_page=1' }
            else { 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' }
            
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $WebClient = New-Object System.Net.WebClient
            
            function Get-LatestUrl
            {
                ((Invoke-WebRequest $apiLatestUrl -UseBasicParsing | ConvertFrom-Json).assets | Where-Object { $_.name -match '^Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle$' }).browser_download_url
            }
            
            function Get-LatestHash
            {
                $shaUrl = ((Invoke-WebRequest $apiLatestUrl -UseBasicParsing | ConvertFrom-Json).assets | Where-Object { $_.name -match '^Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.txt$' }).browser_download_url
                
                $shaFile = Join-Path -Path $tempFolder -ChildPath 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.txt'
                $WebClient.DownloadFile($shaUrl, $shaFile)
                
                Get-Content $shaFile
            }
            
            $desktopAppInstaller = @{
                fileName = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
                url	     = $(Get-LatestUrl)
                hash	 = $(Get-LatestHash)
            }
            
            $vcLibsUwp = @{
                fileName = 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
                url	     = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
                hash	 = '9BFDE6CFCC530EF073AB4BC9C4817575F63BE1251DD75AAA58CB89299697A569'
            }
            $uiLibsUwp = @{
                fileName = 'Microsoft.UI.Xaml.2.7.zip'
                url	     = 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.0'
                hash	 = '422FD24B231E87A842C4DAEABC6A335112E0D35B86FAC91F5CE7CF327E36A591'
            }

            $dependencies = @($desktopAppInstaller, $vcLibsUwp, $uiLibsUwp)
            
            Write-Host '--> Checking dependencies'
            
            foreach ($dependency in $dependencies)
            {
                $dependency.file = Join-Path -Path $tempFolder -ChildPath $dependency.fileName
                #$dependency.pathInSandbox = (Join-Path -Path $tempFolderName -ChildPath $dependency.fileName)
                
                # Only download if the file does not exist, or its hash does not match.
                if (-Not ((Test-Path -Path $dependency.file -PathType Leaf) -And $dependency.hash -eq $(Get-FileHash $dependency.file).Hash))
                {
                    Write-Host "`t- Downloading: `n`t$($dependency.url)"
                    
                    try
                    {
                        $WebClient.DownloadFile($dependency.url, $dependency.file)
                    }
                    catch
                    {
                        #Pass the exception as an inner exception
                        throw [System.Net.WebException]::new("Error downloading $($dependency.url).", $_.Exception)
                    }
                    if (-not ($dependency.hash -eq $(Get-FileHash $dependency.file).Hash))
                    {
                        throw [System.Activities.VersionMismatchException]::new('Dependency hash does not match the downloaded file')
                    }
                }
            }
            
            # Extract Microsoft.UI.Xaml from zip (if freshly downloaded).
            # This is a workaround until https://github.com/microsoft/winget-cli/issues/1861 is resolved.
            
            if (-Not (Test-Path (Join-Path -Path $tempFolder -ChildPath \Microsoft.UI.Xaml.2.7\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx)))
            {
                Expand-Archive -Path $uiLibsUwp.file -DestinationPath ($tempFolder + '\Microsoft.UI.Xaml.2.7') -Force
            }
            $uiLibsUwp.file = (Join-Path -Path $tempFolder -ChildPath \Microsoft.UI.Xaml.2.7\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx)
            Add-AppxPackage -Path $($desktopAppInstaller.file) -DependencyPath $($vcLibsUwp.file), $($uiLibsUwp.file)
            # Clean up files
            Remove-Item $tempFolder -recurse -force
    }
    # Call the Install-WinGet function to perform the installation
    Install-WinGet
'@

    # Name for Temp Script.
    $tmpScript = "WingetScript.ps1"
    
    # Ensure the automation directory exists
    if (!(Test-Path "$env:systemdrive\automation")) {
        New-Item "$env:systemdrive\automation" -ItemType Directory | Out-Null
    }

    # Write the script block to a file in the automation directory
    $scriptBlock | Out-File "$env:systemdrive\automation\$tmpScript"

    # Create the scheduled task action to run the PowerShell script
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-executionpolicy bypass -WindowStyle minimized -file %SYSTEMDRIVE%\automation\$tmpScript"

    # Create the scheduled task trigger to run at log on
    $trigger = New-ScheduledTaskTrigger -AtLogOn

    # Get the current user's username to set as the principal of the task
    $UserId = Get-LoggedOnUser
    $principal = New-ScheduledTaskPrincipal -UserId $UserId

    # Create the scheduled task
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal

    # Register and start the scheduled task
    Register-ScheduledTask RunScript -InputObject $task
    Start-ScheduledTask -TaskName RunScript

    # Initialize a loop to check the task status
    do {
        # Retrieve the current status of the scheduled task
        $taskStatus = (Get-ScheduledTask -TaskName RunScript).State

        # Check if the task is still running
        if ($taskStatus -eq 'Running') {
            # Task is still running, wait for a specified time before checking again
            Start-Sleep -Seconds 30
        }
    } while ($taskStatus -eq 'Running')

    # Unregister and remove the scheduled task and script file
    Unregister-ScheduledTask -TaskName RunScript -Confirm:$false
    Remove-Item "$env:systemdrive\automation\$tmpScript"
}


function Test-WingetAppID {
    <#
    .SYNOPSIS
        Checks if a given AppID exists in the winget repository.

    .DESCRIPTION
        This PowerShell function uses the winget CLI to search for a specified AppID in the winget repository.
        It returns $true if the AppID exists, and $false if it does not. An optional parameter allows specifying
        a custom path to the winget executable. The function is updated to better handle execution under the System account
        and includes a timeout feature.

    .PARAMETER AppID
        The AppID of the software package to check in the winget repository.

    .PARAMETER WingetPath
        Optional. The full path to the winget executable. If not provided, it assumes winget is in the system PATH.

    .NOTES
        Requires the winget CLI to be installed. If WingetPath is not provided, winget must be accessible in the system PATH.
        The function is designed to work across different Windows environments and OS languages, including under the System account.

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppID,

        [Parameter(Mandatory=$false)]
        [string]$WingetPath
    )

    # Initialize result variable
    [Boolean]$fnResult = $false

    # Input validation for AppID parameter
    if (-not [string]::IsNullOrWhiteSpace($AppID)) {
        try {
            # Determine the winget command based on whether a custom path is provided
            $wingetCommand = if ([string]::IsNullOrWhiteSpace($WingetPath)) { "winget" } else { $WingetPath }

            # Execute winget command and capture the output
            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = $wingetCommand
            $processInfo.Arguments = "search --id $AppID"
            $processInfo.RedirectStandardOutput = $true
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $processInfo

            # Start the process
            $process.Start() | Out-Null

            # Wait for the process to exit with a timeout
            $timeout = 90000 # 90 seconds
            $process.WaitForExit($timeout) | Out-Null

            if (!$process.HasExited) {
                Write-Warning "Process did not complete within the timeout period."
                $process.Kill() | Out-Null
                $fnResult = $false
            }

            # Read output
            $wingetOutput = $process.StandardOutput.ReadToEnd()

            # Check if AppID exists in the repository
            if ($wingetOutput -match ".*\b$AppID\b.*") {
                $fnResult = $true
            } elseif ($wingetOutput -match "No package found matching input criteria") {
                Write-Warning "$AppID package not found."
                $fnResult = $false
            } else {
                Write-Warning "An error occurred while executing winget: $wingetOutput. "
                $fnResult = $false
            }
        } catch {
            # Catch any exceptions that occur during execution
            Write-Error "An error occurred while searching for the AppID with winget: $_"
            $fnResult = $false
        }
    } else {
        # The input AppID is null, empty, or whitespace
        Write-Error "The AppID parameter cannot be null or empty."
        $fnResult = $false
    }

    # Return the result
    return $fnResult
}



function Install-WingetApp {
    <#
    .SYNOPSIS
        Installs an application using the Windows Package Manager (winget).

    .DESCRIPTION
        The Install-WingetApp function installs an application on a Windows machine
        using the winget command-line tool. It requires the application ID as input
        and optionally takes a path to the winget executable. If the path is not provided,
        it attempts to locate winget automatically. The function returns an object containing
        the result of the installation and a summary of the operation.

    .PARAMETER AppID
        The ID of the application to install, as recognized by winget.

    .PARAMETER WingetPath
        The full path to the winget executable. If not provided, the function will attempt to locate it.

    .EXAMPLE
        $result = Install-WingetApp -AppID "Microsoft.VisualStudioCode" -WingetPath "C:\path\to\winget.exe"

    .OUTPUTS
        PSCustomObject containing the result code and a summary of the installation process.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppID,

        [string]$WingetPath
    )

    # Initialize the detect summary for this function
    $functionDetectSummary = @()

    # Attempt to locate winget if the path is not provided
    if (-not $WingetPath) {
        $WingetPath = (Get-Command winget).Source
    }

    # Try to install the application using winget
    try {
        # Create a temporary file to capture the output of the installation process
        $tempFile = New-TemporaryFile
        Write-Host "Initiating App $AppID Installation"

        # Start the winget process with the appropriate arguments for silent installation
        $processResult = Start-Process -FilePath "$WingetPath" -ArgumentList "install -e --id `"$AppID`" --scope=machine --silent --accept-package-agreements --accept-source-agreements --force" -NoNewWindow -Wait -RedirectStandardOutput $tempFile.FullName -PassThru

        # Capture the exit code and output from the winget process
        $exitCode = $processResult.ExitCode
        $installInfo = Get-Content $tempFile.FullName
        Remove-Item $tempFile.FullName

        # Check the exit code to determine if the installation was successful
        if ($exitCode -eq 0) {
            Write-Host "Winget successfully installed application."
            $functionDetectSummary += "Installed $AppID via Winget. "
            $result = 0
        } else {
            Write-Host "Error during installation, exit code: $exitCode."
            $functionDetectSummary += "Error during installation, exit code: $exitCode. "
            $result = 1
        }
    }
    catch {
        # Catch any exceptions that occur during the installation process
        Write-Host "Encountered an error during installation: $_"
        $functionDetectSummary += "Installation failed with error: $_ "
        $result = 1
    }

    # Return a custom object with both result and detect summary
    return [PSCustomObject]@{
        Result = $result
        DetectSummary = $functionDetectSummary
    }
}


function Uninstall-WingetApp {
    <#
    .SYNOPSIS
        Uninstalls an application using the Windows Package Manager (winget) with an option for custom uninstall commands.

    .DESCRIPTION
        The Uninstall-WingetApp function is designed to uninstall applications from a Windows machine
        using the winget command-line tool. While it works with most applications, it is crucial to conduct
        thorough testing before deployment. Certain applications, in my case, like Citrix Workspace, may not support
        silent uninstallation through winget directly. In such cases, refer to custom solutions or alternative
        methods of silent uninstallation. 
        
        An example of troubleshooting the silent uninstallation of Citrix Workspace
        can be found at the following URL: https://www.reddit.com/r/sysadmin/comments/144jle7/winget_silent_uninstall_citrixworkspace/

    .PARAMETER AppID
        The ID of the application to uninstall, as recognized by winget.

    .PARAMETER WingetPath
        The full path to the winget executable. If not provided, the function will attempt to locate it.

    .EXAMPLE
        $result = Uninstall-WingetApp -AppID "Microsoft.VisualStudioCode" -WingetPath "C:\path\to\winget.exe"

    .OUTPUTS
        PSCustomObject containing the result code and a summary of the uninstallation process.

    .NOTES
        It is recommended to verify the behavior of the uninstallation process with each specific application.
        For applications with known issues consult external resources or community forums
        for potential workarounds and script modifications.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppID,

        [string]$WingetPath
    )

    # Initialize the detect summary for this function
    $functionDetectSummary = @()

    # Attempt to locate winget if the path is not provided
    if (-not $WingetPath) {
        $WingetPath = (Get-Command winget).Source
    }

    # Try to uninstall the application using winget
    try {
        # Create a temporary file to capture the output of the uninstallation process
        $tempFile = New-TemporaryFile
        Write-Host "Initiating App $AppID Uninstallation"

        # Start the winget process with the appropriate arguments for silent uninstallation
        $processResult = Start-Process -FilePath "$WingetPath" -ArgumentList "uninstall --id `"$AppID`" --silent --force" -NoNewWindow -Wait -RedirectStandardOutput $tempFile.FullName -PassThru

        # Capture the exit code and output from the winget process
        $exitCode = $processResult.ExitCode
        $uninstallInfo = Get-Content $tempFile.FullName
        Remove-Item $tempFile.FullName

        # Check the exit code to determine if the uninstallation was successful
        if ($exitCode -eq 0) {
            Write-Host "Winget successfully uninstalled application."
            $functionDetectSummary += "Uninstalled $AppID via Winget. "
            $result = 0
        } else {
            Write-Host "Error during uninstallation, exit code: $exitCode."
            $functionDetectSummary += "Application may not be installed or other error occurred, exit code: $exitCode. "
            $result = 1
        }
    }
    catch {
        # Catch any exceptions that occur during the uninstallation process
        Write-Host "Encountered an error during uninstallation: $_"
        $functionDetectSummary += "Uninstallation failed with error: $_ "
        $result = 1
    }

    # Return a custom object with both result and detect summary
    return [PSCustomObject]@{
        Result = $result
        DetectSummary = $functionDetectSummary
    }
}


#endregion Functions

#region Main

#region Initialization
$wingetPath = ""                # Path to Winget executable
$detectSummary = ""             # Script execution summary
$result = 0                     # Exit result (default to 0)
$WingetAppID = $WingetAppID     # Winget Application ID
$processResult = $null          # Winget process result
$exitCode = $null               # Software installation exit code
$installInfo                    # Information about the Winget installation process
[boolean]$appExists = $false    # Records if Winget App exists, or not.
#endregion Initialization

# Make the log easier to read
Write-Host `n`n

# Invoke the function to ensure we're running in a 64-bit environment if available
Invoke-Ensure64bitEnvironment
Write-Host "Script running in 64-bit environment."

# Find if Visual C++ redistributable is installed using Install-VisualCIfMissing function and capture the result
$vcInstalled = Install-VisualCIfMissing

if ($vcInstalled) {
    $detectSummary += "Visual C++ Redistributable installed. "
} else {
    $detectSummary += "Failed to verify or install Visual C++ Redistributable. "
    $result = 5
}

# Check if Winget is available and, if not, find it
$wingetPath = (Get-Command -Name winget -ErrorAction SilentlyContinue).Source

if (-not $wingetPath) {
    Write-Host "Winget not detected, attempting to locate in device..."
    $wingetPath = Find-WingetPath
}

# If not present, try to install it
if (-not $wingetPath) {
    Write-Host "Trying to install latest Winget using Install-WingetAsSystem...."
    Install-WingetAsSystem
    $wingetPath = Find-WingetPath
}

# If still not present, notify, or maybe it did find it, yei!!
if (-not $wingetPath) {
    Write-Host "Winget (Windows Package Manager) is absent on this device." 
    $detectSummary += "Winget NOT detected. "
    $result = 6
} else {
    $detectSummary += "Winget located at $wingetPath. "
    $result = 0
}

# Validate if requested App exists or is available in Winget repository
Write-Host "Verifying application $WingetAppID exists in repository."
try {
    $tstWinget = Test-WingetAppID -AppID $WingetAppID -WingetPath $wingetPath
    $appExists = [bool]$tstWinget
} catch {
    Write-Error "Error occurred: $_"
    $appExists = $false
}
#$appExists = Test-WingetAppID -AppID $WingetAppID -WingetPath $wingetPath

if (-not $appExists) {
    $detectSummary += "Winget App ID not found. "
    $result = 1
} else {
    Write-Host "Found App $WingetAppID in Winget repository. "
}

# Use Winget to install or uninstall desired software
if ($result -eq 0) {
    if ($Uninstall) {
        # Call the uninstall function with the WingetPath parameter
        Write-Host "Uninstalling Winget application with AppID: $WingetAppID"
        $functionResult = Uninstall-WingetApp -AppID $WingetAppID -WingetPath $wingetPath
    } else {
        # Call the install function with the WingetPath parameter
        Write-Host "Starting installation of the Winget application with AppID: $WingetAppID"
        $functionResult = Install-WingetApp -AppID $WingetAppID -WingetPath $WingetPath
    }
}

# Extract the result and detect summary from the returned object
$result = $functionResult.Result
$detectSummary += $functionResult.DetectSummary

# Simplify reading in the AgentExecutor Log
Write-Host `n`n

# Output the final results
if ($result -eq 0) {
    Write-Host "OK $([datetime]::Now) : $detectSummary"
    Exit 0
} elseif ($result -eq 1) {
    Write-Host "FAIL $([datetime]::Now) : $detectSummary"
    Exit 1
} else {
    Write-Host "NOTE $([datetime]::Now) : $detectSummary"
    Exit 0
}

#endregion Main
