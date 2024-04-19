<#
.SYNOPSIS
Reset-WindowsUpdateComponentsAndAutopatchPolicyConflict.ps1 - Resets the Windows Update components

.DESCRIPTION 
This script will reset all of the Windows Updates components to Default Settings and helps with AutoPatchConfigurationsIssue

.OUTPUTS
Results are printed to the console and also Ouput file under C:\WindowsUpdateComponentsAndAutopatchPolicyConflict.txt

.NOTES
Written by: Rudra Prasad Paul
#>


# Path to the file you want to check
$fileToCheck = "C:\WindowsUpdateComponentsAndAutopatchPolicyConflict.txt"

# Check if script is running with admin privileges
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not running with admin privileges, exit script
if (-not (Test-Admin)) {
    Write-Warning "This script requires administrative privileges. Please run it as an administrator."
    return
}

# Script continues here if running with admin privileges


function Log-Message {
    param (
        [string]$Message
    )
    # Get the current date and time
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # Write the message to the log file
    Add-Content -Path $fileToCheck -Value "$timestamp - $Message"
}

function Output {
    param (
        [string]$Message
    )
    # Write the message to the log file
    Write-Host $Message
    Log-Message $Message

}


# Check if the file exists
if (Test-Path $fileToCheck) {
    Output "File already exists. Deleting..."
    # Delete the existing file
    Remove-Item $fileToCheck -Force
    Output "File deleted."
}

# Create a new text file
New-Item -Path $fileToCheck -ItemType "file" -Force
Output "New file created successfully."

Output "Starting script execution..."

Output "Stopping Windows Update Services..."



Output "Stopping BITS service..."
Stop-Service -Name BITS
Output "BITS service stopped."


Output "Stopping wuauserv service..."
Stop-Service -Name wuauserv
Output "wuauserv service stopped."

Output "Stopping appidsvc service..."
Stop-Service -Name appidsvc
Output "appidsvc service stopped."

Output "Stopping cryptsvc service..."
Stop-Service -Name cryptsvc
Output "cryptsvc service stopped."


# Remove Windows Update policy registry keys
Output "Removing conflicting AutoPatch Update policy registry keys..."


if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue) {
        # Remove Windows Update policy registry key "DoNotConnectToWindowsUpdateInternetLocations"
        Output "Removing DoNotConnectToWindowsUpdateInternetLocations registry key..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue
        Output "DoNotConnectToWindowsUpdateInternetLocations registry key removed."
}
else {
    Output "DoNotConnectToWindowsUpdateInternetLocations registry key is not found."
}

if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue) {
        # Remove Windows Update policy registry key "DoNotConnectToWindowsUpdateInternetLocations"
        Output "Removing DisableWindowsUpdateAccess registry key..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue
        Output "DisableWindowsUpdateAccess registry key removed."
}
else {
    Output "DisableWindowsUpdateAccess registry key is not found."
}

if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue) {
        # Remove Windows Update policy registry key "DoNotConnectToWindowsUpdateInternetLocations"
        Output "Removing WUServer registry key..."
        Remove-ItemProperty -Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
        Output "WUServer registry key removed."
}
else {
    Output "WUServer registry key is not found."
}

if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction SilentlyContinue) {
        # Remove Windows Update policy registry key "DoNotConnectToWindowsUpdateInternetLocations"
        Output "Removing UseWUServer registry key..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction SilentlyContinue
        Output "UseWUServer registry key removed."
}
else {
    Output "UseWUServer registry key is not found."
}

if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue) {
        # Remove Windows Update policy registry key "DoNotConnectToWindowsUpdateInternetLocations"
        Output "Removing NoAutoUpdate registry key..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        Output "NoAutoUpdate registry key removed."
}
else {
    Output "NoAutoUpdate registry key is not found."
}



Output "Renaming the Software Distribution and CatRoot Folder..."
Rename-Item $env:systemroot\SoftwareDistribution SoftwareDistribution.bak -ErrorAction SilentlyContinue
Output "Software Distribution folder renamed."
Rename-Item $env:systemroot\System32\Catroot2 catroot2.bak -ErrorAction SilentlyContinue
Output "CatRoot2 folder renamed."


Output "Remove QMGR Data file..."
Remove-Item "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue
Output "QMGR Data file removed."

Output "Resetting the Windows Update Services to defualt settings..."
"sc.exe sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
"sc.exe sdset wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"


Output "Resetting the WinSock..."
netsh winsock reset
netsh winhttp reset proxy
Output "WinSock reset completed"


Output "Delete all BITS jobs for current user..."
Get-BitsTransfer | Remove-BitsTransfer
Output "BITS jobs deleted for the current user"


Output "Starting Windows Update Services..."

# Start BITS service
Output "Starting BITS service..."
Start-Service -Name BITS
Output "BITS service started."


# Start wuauserv service
Output "Starting wuauserv service..."
Start-Service -Name wuauserv
Output "wuauserv service started."


# Start appidsvc service
Output "Starting appidsvc service..."
Start-Service -Name appidsvc
Output "appidsvc service started."

# Start cryptsvc service
Output "Starting cryptsvc service..."
Start-Service -Name cryptsvc
Output "cryptsvc service started."

Output "Script execution completed."