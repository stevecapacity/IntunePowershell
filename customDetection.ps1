# Set variables
$autopilotRegistry = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\AutoPilot'
$autopilotTenant = $autopilotRegistry.CloudAssignedTenantDomain

$firefox = $false
if("C:\Program Files\Mozilla Firefox\firefox.exe")
{
    $firefox = $true
}

# Create json hash array
$hash = @{
    AutopilotTenant = $autopilotTenant;
    FirefoxInstalled = $firefox
}

# return and convert to JSON
return $hash | ConvertTo-Json -Compress