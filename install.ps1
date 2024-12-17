$AppName = "AppDisplayNameHere"
$LogFile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Applications\$AppName\install.log"
# InstallerPath should be $PSScriptRoot\RelativePath\To\File.ext
$InstallerPath = "$PSScriptRoot\setup.exe"
$InstallerArgs = "/s"
$SuccessReturns = @(0, 1707, 3010, 1641)

if (-Not (Test-Path $LogFile)) {
    New-Item -Path $LogFile -ItemType File -Force
}

Function Add-TextToCMLog {
    ##########################################################################################################
    <#
.SYNOPSIS
   Log to a file in a format that can be read by Trace32.exe / CMTrace.exe

.DESCRIPTION
   Write a line of data to a script log file in a format that can be parsed by Trace32.exe / CMTrace.exe

   The severity of the logged line can be set as:

        1 - Information
        2 - Warning
        3 - Error

   Warnings will be highlighted in yellow. Errors are highlighted in red.

   The tools to view the log:

   SMS Trace - http://www.microsoft.com/en-us/download/details.aspx?id=18153
   CM Trace - Installation directory on Configuration Manager 2012 Site Server - <Install Directory>\tools\

.EXAMPLE
   Add-TextToCMLog c:\output\update.log "Application of MS15-031 failed" Apply_Patch 3

   This will write a line to the update.log file in c:\output stating that "Application of MS15-031 failed".
   The source component will be Apply_Patch and the line will be highlighted in red as it is an error
   (severity - 3).

#>
    ##########################################################################################################

    # Define and validate parameters
    [CmdletBinding()]
    Param(
        #The information to log
        [parameter(Mandatory = $True)]
        [String]$Value,

        #The source of the error
        [parameter(Mandatory = $True)]
        [String]$Component,

        #The severity (1 - Information, 2- Warning, 3 - Error)
        [parameter(Mandatory = $True)]
        [ValidateRange(1, 3)]
        [Single]$Severity
    )

    if ($Severity -eq 1) {
        Write-Host $Value
    }
    elseif ($Severity -eq 2) {
        Write-Warning $Value
    }
    elseif ($Severity -eq 3) {
        Write-Error $Value
    }

    # Obtain UTC offset
    $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime
    $DateTime.SetVarDate($(Get-Date))
    $UtcValue = $DateTime.Value
    $UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)

    # Create the line to be logged
    $LogLine = "<![LOG[$Value]LOG]!>" + `
        "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " + `
        "date=`"$(Get-Date -Format M-d-yyyy)`" " + `
        "component=`"$Component`" " + `
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
        "type=`"$Severity`" " + `
        "thread=`"$($pid)`" " + `
        "file=`"`">"

    # Append the line to the log text
    Add-Content -Path $LogFile -Value $LogLine
}

function Get-InstalledApplications() {
    [cmdletbinding(DefaultParameterSetName = 'GlobalAndAllUsers')]

    Param (
        [Parameter(ParameterSetName="Global")]
        [switch]$Global,
        [Parameter(ParameterSetName="GlobalAndCurrentUser")]
        [switch]$GlobalAndCurrentUser,
        [Parameter(ParameterSetName="GlobalAndAllUsers")]
        [switch]$GlobalAndAllUsers,
        [Parameter(ParameterSetName="CurrentUser")]
        [switch]$CurrentUser,
        [Parameter(ParameterSetName="AllUsers")]
        [switch]$AllUsers
    )

    # Excplicitly set default param to True if used to allow conditionals to work
    if ($PSCmdlet.ParameterSetName -eq "GlobalAndAllUsers") {
        $GlobalAndAllUsers = $true
    }

    # Check if running with Administrative privileges if required
    if ($GlobalAndAllUsers -or $AllUsers) {
        $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($RunningAsAdmin -eq $false) {
            Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 3 -Value "Finding all user applications requires administrative privileges"
            break
        }
    }

    # Empty array to store applications
    $Apps = @()
    $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    # Retreive globally insatlled applications
    if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
        Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 1 -Value "Processing global hive"
        $Apps += Get-ItemProperty "HKLM:\$32BitPath"
        $Apps += Get-ItemProperty "HKLM:\$64BitPath"
    }

    if ($CurrentUser -or $GlobalAndCurrentUser) {
        Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 1 -Value "Processing current user hive"
        $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
        $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
    }

    if ($AllUsers -or $GlobalAndAllUsers) {
        Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 1 -Value "Collecting hive data for all users"
        $AllProfiles = Get-CimInstance Win32_UserProfile | Select-Object LocalPath, SID, Loaded, Special | Where-Object {$_.SID -like "S-1-5-21-*"}
        $MountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $true}
        $UnmountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $false}

        Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 1 -Value "Processing mounted hives"
        $MountedProfiles | ForEach-Object {
            $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
            $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
        }

        Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 1 -Value "Processing unmounted hives"
        $UnmountedProfiles | ForEach-Object {

            $Hive = "$($_.LocalPath)\NTUSER.DAT"
            Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 1 -Value " -> Mounting hive at $Hive"

            if (Test-Path $Hive) {
            
                REG LOAD HKU\temp $Hive

                $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
                $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"

                # Run manual GC to allow hive to be unmounted
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
            
                REG UNLOAD HKU\temp

            } else {
                Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 2 -Value "Unable to access registry hive at $Hive"
            }
        }
    }

    Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 1 -Value "Returning applications ${$Apps}"

    return $Apps
}

# Start installation
Add-TextToCMLog -Component "Install $AppName" -Severity 1 -Value "Starting installation of $AppName"
$ExitCode = 0
try {
    $installer = Start-Process -FilePath "$InstallerPath" -ArgumentList $InstallerArgs -Wait -PassThru -Verb RunAs
    Add-TextToCMLog -Component "Install $AppName" -Severity 1 -Value "Installer exited with code $($installer.ExitCode)"
    $ExitCode = $installer.ExitCode
} catch {
    Add-TextToCMLog -Component "Install $AppName" -Severity 3 -Value "Installation of $AppName failed. Error: $_"
    exit 1
}

# Verify installation
$App = Get-InstalledApplications -GlobalAndAllUsers | Where-Object {$_.DisplayName -like $AppName}
if ($App) {
    Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 1 -Value "$AppName is installed"
    Add-TextToCMLog -Component "Install $AppName" -Severity 1 -Value "Installation of $AppName completed successfully."
}
else {
    Add-TextToCMLog -Component "Get-InstalledApplications" -Severity 2 -Value "$AppName was not detected after installation."
    Add-TextToCMLog -Component "Install $AppName" -Severity 3 -Value "Installation of $AppName failed."
    $ExitCode = 0 # Exit 0 here so Intune fails on the detection script post install.
}

# Exit with appropriate code
$FinalSeverity = 1
if ($ExitCode -notin $SuccessReturns) {
    $FinalSeverity = 3
}
Add-TextToCMLog -Component "Install $AppName" -Severity $FinalSeverity -Value "Exiting installation of $AppName with exit code $ExitCode"
exit $ExitCode