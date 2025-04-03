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

Add-Type -AssemblyName PresentationFramework

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


[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="App Install Status"
        Height="500" Width="600"
        WindowStartupLocation="CenterScreen"
        Background="White"
        ResizeMode="NoResize"
        WindowStyle="SingleBorderWindow">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,10">
            <Image Source=".\LOGO-BADGE.jpeg" Height="40" Width="40" Margin="0,0,10,0"/>
            <TextBlock Text="Company Name" FontSize="20" FontWeight="Bold" VerticalAlignment="Center"/>
        </StackPanel>

        <!-- Message -->
        <TextBlock Grid.Row="1"
                   Text="Welcome to your new PC. We're finishing up the rest of your app installs. Check back here for progress."
                   FontSize="12" Margin="5" TextWrapping="Wrap" HorizontalAlignment="Center"/>

        <!-- Dynamic Status Panel -->
        <StackPanel Name="AppStatusPanel" Grid.Row="2" Orientation="Vertical" Margin="0,10,0,0"/>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Map elements
$AppStatusPanel = $window.FindName("AppStatusPanel")

foreach($App in $AppStatusList)
{
    $status = switch($App.EnforcementState)
    {
        1000 { "Installed"; [System.Windows.Media.Brushes]::Green }
        2000 { "Pending"; [System.Windows.Media.Brushes]::Orange }
        5000 { "Failed"; [System.Windows.Media.Brushes]::Red }
        Default { "Unknown"; [System.Windows.Media.Brushes]::DarkGray }
    }

    $statusText = $status[0]
    $statusColor = $status[1]

    # Create row stack
    $row = New-Object System.Windows.Controls.StackPanel
    $row.Orientation = "Horizontal"
    $row.Margin = "0,5,0,0"

    # App name
    $nameText = New-Object System.Windows.Controls.TextBlock
    $nameText.Text = $App.DisplayName
    $nameText.Width = 180
    $nameText.VerticalAlignment = "Center"

    # Progress bar
    $progress = New-Object System.Windows.Controls.ProgressBar
    $progress.Width = 250
    $progress.Height = 10
    $progress.Margin = "10,0,10,0"
    $progress.Value = switch($statusText)
    {
        "Installed" { 100 }
        "Pending" { 50 }
        "Failed" { 0 }
        Default { 0 }
    }

    # Status text
    $statusBlock = New-Object System.Windows.Controls.TextBlock
    $statusBlock.Text = $statusText
    $statusBlock.Width = 80
    $statusBlock.Foreground = $statusColor
    $statusBlock.VerticalAlignment = "Center"

    # Add to row
    $row.Children.Add($nameText)
    $row.Children.Add($progress)
    $row.Children.Add($statusBlock)

    # Add row to panel
    $AppStatusPanel.Children.Add($row)
}

$window.ShowDialog() | Out-Null