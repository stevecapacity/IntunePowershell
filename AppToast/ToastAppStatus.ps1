<#
.SYNOPSIS
Display Window to keep users informed of apps and policy being applied from Intune.

.DESCRIPTION
This script is designed to be run as a scheduled task after Autopilot provisioning to keep users informed of apps and policy being applied from Intune. The script will check for assigned applications and display a pop up Window showing status.

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