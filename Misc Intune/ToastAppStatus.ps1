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
        [string]$tenantName = "<tenantName>"
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
function Get-IntuneAppStatus()
{
    Params(
        [string]$Win32RegPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
    )
    $AppStatusList = @()
    if(Test-Path $Win32RegPath)
    {
        $ParentGUIDs = Get-ChildItem -Path $Win32RegPath | Select-Object -ExpandProperty PSChildName
        $AppGUIDs = $ParentGUIDs | Where-Object { $_ -match "^[0-9a-fA-F\-]{36}$" }

        foreach($AppGUID in $AppGUIDs)
        {
            $ParentSubKeys = Get-ChildItem -Path "$($Win32RegPath)\$($AppGUID)" | Select-Object -ExpandProperty PSChildName
            $SubKeys = $ParentSubKeys | Where-Object { $_ -match "^[0-9a-fA-F\-]{36}(_d\+)?$" } | ForEach-Object { if ( $_ -match "([0-9a-fA-F\-]{36})") { $matches[1] } }
            foreach($SubKey in $SubKeys)
            {
                $RegPath = "$($Win32RegPath)\$($AppGUID)\$($SubKey)_1\EnforcementStateMessage"
                $RegValue = "EnforcementStateMessage"

                if(Test-Path $RegPath)
                {
                    try 
                    {
                        $EnforcementStateMessage = Get-ItemProperty -Path $RegPath -Name $RegValue | Select-Object -ExpandProperty $RegValue
                        $EnforcementStateObject = $EnforcementStateMessage | ConvertFrom-Json
                        $EnforcementState = $EnforcementStateObject.EnforcementState
    
                        $AppStatusList += [PSCustomObject]@{
                            DisplayName = (Invoke-RestMethod -Method Get -Uri "$($GraphAPIBase)/deviceAppManagement/mobileApps/$($SubKey)" -Headers $Headers).displayName
                            AppId = $SubKey
                            EnforcementState = $EnforcementState
                        }                        
                    }
                    catch 
                    {
                        $message = $Exception.Message
                        log "Error getting app status: $message"
                    }   
                }
                else
                {
                    log "Registry key not found: $RegPath"
                }
            }
        }
    }
    else
    {
        log "Registry path not found: $Win32RegPath"
    }
    return $AppStatusList
}


### Check MDM policies
<#$MDMCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device" -ErrorAction SilentlyContinue
if (-not $MDMCheck) {
    $PolicyStatus = "MDM Policies Not Applied"
} else {
    $PolicyStatus = "MDM Policies Applied"
}
log "MDM policy status: $PolicyStatus"#>

### Generate notification if issues found
if ($MissingApps.Count -gt 0 -or $PolicyStatus -eq "MDM Policies Not Applied") {
    $Message = "The following issues were found:`n"
    if ($MissingApps.Count -gt 0) { $Message += "Missing Apps: " + ($MissingApps -join ", ") + "`n" }
    if ($PolicyStatus -eq "MDM Policies Not Applied") { $Message += "MDM policies not applied!" }
    
    New-BurntToastNotification -Text "Intune Compliance Check", $Message
    log "Issues detected. Notification displayed."
} else {
    New-BurntToastNotification -Text "Intune Compliance Check", "All assigned applications and policies are applied successfully."
    log "All assigned applications and policies are applied successfully."
}