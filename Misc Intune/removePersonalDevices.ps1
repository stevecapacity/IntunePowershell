function log()
{
    Param(
        [string]$message
    )
    $date = Get-Date -Format "yyyy-MM-dd hh:mm:ss tt"
    Write-Output "$date - $message"
}


# verify NuGet installed
$nuget = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction Ignore
if(-not($nuget))
{
    log "NuGet not found, installing..."
    Install-PackageProvider -Name NuGet -Confirm:$false -Force
}
else
{
    log "NuGet already installed."
}

# verify Microsoft.Graph module
$graphModule = Get-InstalledModule -Name Microsoft.Graph -ErrorAction Ignore
if(-not($graphModule))
{
    log "Microsoft Graph module not found, installing now..."
    Install-Module -Name Microsoft.Graph -Confirm:$false -Force
}
else
{
    log "Microsoft Graph module already installed."
}

<# Authentication method 1 - app reg and client secret
# appreg goes here
$clientID = "<CLIENT ID>"
# client secret goes here
$clientSecret = "<CLIENT SECRET>"
$tenantID = "<TENANT ID>"

$SecureClientSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$ClientSecureCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientID, $SecureClientSecret
Connect-MgGraph -ClientSecretCredential $ClientSecureCredential -TenantId $tenantID
#>

# Authentication method 2 - User sign in
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All"

# Get personal Intune devices call to graph
$personalDevices = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=ownerType eq 'personal'").value

# Remove personal from Intune devic
foreach($device in $personalDevices)
{
    log "Found personal device $($device.deviceName)."
    $id = $device.id
    try 
    {
        log "Attempting to delete $($device.deviceName) from tenant..."
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($id)"
        log "Device $($device.deviceName) was deleted."        
    }
    catch 
    {
        log "Error trying to remove device $($device.deviceName): $_"
    }
}



