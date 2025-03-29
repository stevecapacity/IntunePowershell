<#
.SYNOPSIS
Display toast notification after Autopilot provisioning to keep users informed of apps and policy being applied from Intune.

.DESCRIPTION
This script is designed to be run as a scheduled task after Autopilot provisioning to keep users informed of apps and policy being applied from Intune. The script will check for assigned applications and MDM policies and display a toast notification if any issues are found.

.PARAMETER message
Microsoft Graph API client ID, client secret, and tenant name.
The message to display in the toast notification.

.EXAMPLE
IntuneToast.ps1 -clientId "12345678-1234-1234-1234-123456789012" -clientSecret "client_secret" -tenantName "tenantName"

.NOTES
File Name      : IntuneToast.ps1
Author         : Justin Rice, Steve Weiner
Prerequisite   : PowerShell V5
Copyright 2025 - Rubix, LLC. All rights reserved.
#>

# Log function
function log {
    param (
        [string]$message
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $message = "$time - $message"
    Write-Output $message
}

# Check for nuget package provider
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) 
{
    Install-PackageProvider -Name NuGet -Force -Confirm:$false
}

# Install modules if not already installed
$modules = @(
    "BurntToast",
    "RunAsUser"
)

foreach ($module in $modules) 
{
    if (-not (Get-Module -Name $module -ListAvailable)) 
    {
        Install-Module -Name $module -Force -AllowClobber
    }
    Import-Module $module
}



# Graph authenticate function
function msGraphAuthenticate()
{
    [CmdletBinding()]
    Param(
        [string]$clientId = "<client_id>",
        [string]$clientSecret = "<client_secret>",
        [string]$tenantName = "<tenant_name>"
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
    $body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)
    $response = Invoke-RestMethod "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body
    # Get token from OAuth response

    $token = -join ("Bearer ", $response.access_token)

    # Reinstantiate headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")
    $headers = @{'Authorization'="$($token)"}
    return $headers
}

### Authenticate to Graph API
$Headers = msGraphAuthenticate

### Graph base URI
$GraphAPIBase = "https://graph.microsoft.com/beta"

### Get assigned apps through registry

[string]$Win32RegPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
[string]$GraphAPIBase = "https://graph.microsoft.com/beta"
    

$AppStatusList = @()

if(Test-Path $Win32RegPath)
{
    $AppGUIDs = Get-ChildItem -Path $Win32RegPath | Select-Object -ExpandProperty PSChildName | Where-Object { $_ -match "^[0-9a-fA-F\-]{36}$" }

    foreach ($AppGUID in $APPGUIDs)
    {
        $AppGUIDPath = "$($Win32RegPath)\$($AppGUID)"

        if(Test-Path $AppGUIDPath)
        {
            $ParentSubKeys = Get-ChildItem -Path $AppGUIDPath | Select-Object -ExpandProperty PSChildName -ErrorAction SilentlyContinue

            if($ParentSubKeys)
            {
                $SubKeys = $ParentSubKeys | Where-Object { $_ -match "^[0-9a-fA-F\-]{36}" }

                if ($SubKeys)
                {
                    foreach($SubKey in $SubKeys)
                    {
                        if($SubKey -match "^(.*)_1$")
                        {
                            $SubKey = $matches[1]
                        }
                        else
                        {
                            $SubKey = $SubKey
                        }
                        $RegPath = "$($AppGUIDPath)\$($SubKey)_1\EnforcementStateMessage"
                        $RegValue = "EnforcementStateMessage"

                        if(Test-Path $RegPath)
                        {
                            try
                            {
                                $EnforcementStateMessage = Get-ItemProperty -Path $RegPath -Name $RegValue | Select-Object -ExpandProperty $RegValue
                                $EnforcementStateMessage = $EnforcementStateMessage.Trim()

                                if($EnforcementStateMessage -match "^\{")
                                {
                                    try
                                    {
                                        $EnforcementStateObject = $EnforcementStateMessage | ConvertFrom-Json
                                        $EnforcementState = $EnforcementStateObject.EnforcementState                                            
                                        
                                    }
                                    catch
                                    {
                                        log "Error parsing JSON: $_"
                                    }
                                }
                                else
                                {
                                    log "Error: EnforcementStateMessage is not in JSON format"
                                }


                                $GraphUri = "$($GraphAPIBase)/deviceAppManagement/mobileApps/$($SubKey)"
                                $AppDisplayName = (Invoke-RestMethod -Method Get -Uri $GraphUri -Headers $Headers).DisplayName

                                $AppStatusList += [PSCustomObject]@{
                                    DisplayName = $AppDisplayName
                                    AppId = $SubKey
                                    EnforcementState = $EnforcementState
                                }
                            }
                            catch
                            {
                                log "Error retrieving EnforcementState for App GUID: $($SubKey) - $_"
                            }
                        }
                        else
                        {
                            log "Registry key not found: $RegPath"
                        }
                    }
                }
                else
                {
                    log "No valid subkeys found under: $AppGUIDPath"
                }
            }
            else
            {
                log "No subkeys found for App GUID: $AppGUID"
            }
        }
        else
        {
            log "Registry path does not exist: $AppGUIDPath"
        }
    }
    
}
else
{
    log "Registry path not found: $Win32RegPath"
}


# Check if AppStatus returned value
if($null -eq $AppStatusList)
{
    log "No applications found.  Exiting..."
    # Kill task
    Exit 0
}
else
{
    $AppJson = $AppStatusList | ConvertTo-Json -Compress
    log "App status found.  Converting to JSON"
}

# Get current user SID
$CurrentUser = (Get-CimInstance -Class Win32_ComputerSystem | Select-Object UserName).UserName
$SID = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value

# Create a new registry key for the current user
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
$UserRegPath = "HKU\$($SID)\SOFTWARE\AppToast"
New-Item -Path $UserRegPath -Force
New-ItemProperty -Path $UserRegPath -Name "AppStatus" -Value $AppJson -Force


# Function to display toast notification with BurntToast
function Show-ToastNotification()
{
    $Apps = (Get-ItemProperty -Path "HKCU:\SOFTWARE\AppToast" -Name "AppStatus").AppStatus | ConvertFrom-Json

    # Build toast message
    $ToastTitle = "Intune App Installation Status"
    $ToastBody = foreach($App in $Apps)
    {
        $AppName = $App.DisplayName
        $Status = switch ($App.EnforcementState)
        {
            "1000" { "Installed" }
            "5000" { "Failed" }
            "2000" { "Pending" }
            default { "Unknown" }
        }
        "$AppName - $Status"
    } -join "`n"

    # Assemble Toast block
    $ToastScriptBlock = {
        param($ToastBody)

        Import-Module BurntToast -ErrorAction SilentlyContinue
        
        $Text1 = New-BTHeader -Content $ToastTitle
        $Text2 = New-BTText -Content $ToastBody
        $Binding = New-BTBinding -Children $Text1, $Text2
        $Visual = New-BTVisual -BindingGeneric $Binding
        $Content = New-BTContent -Visual $Visual

        Submit-BTNotification
        # Show toast notification
        New-BurntToastNotification -Content $Content -Silent
    }
    Invoke-AsCurrentUser -ScriptBlock $ToastScriptBlock -UseWindowsPowerShell $true
}


# Check AppStatusList for any App that does not have an enforcement state of 1000.  If an app does not have 1000, trigger the Show-ToastNotification function and keep running every minute for up to ten minutes until all apps have an enforcement state of 1000.
$AppStatusList = $AppStatusList | Where-Object { $_.EnforcementState -ne "1000" }
$AppStatusListCount = $AppStatusList.Count
$MaxWaitTime = 10
$WaitTime = 0
$Interval = 60
$StartTime = Get-Date
$EndTime = $StartTime.AddMinutes($MaxWaitTime)

# Show initial toast
Show-ToastNotification

# Loop until all apps have an enforcement state of 1000 or the max wait time is reached
while ($AppStatusListCount -gt 0 -and (Get-Date) -lt $EndTime)
{
    Start-Sleep -Seconds $Interval
    $AppStatusList = Get-ItemProperty -Path "HKCU:\SOFTWARE\AppToast" -Name "AppStatus" | ConvertFrom-Json
    $AppStatusListCount = $AppStatusList.Count

    # Check if all apps have an enforcement state of 1000
    if ($AppStatusListCount -eq 0)
    {
        # All apps have an enforcement state of 1000, exit loop
        break
    }
}

