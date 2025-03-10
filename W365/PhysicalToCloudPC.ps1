# Install Microsoft Graph module if not installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Intune)) {
    Install-Module Microsoft.Graph.Intune -Force -Scope CurrentUser
}


$deviceEndpoint = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Device.Read.All", "User.Read.All"

$devices = Invoke-MgGraphRequest -Method Get -Uri "$($deviceEndpoint)?`$filter=operatingSystem eq 'Windows'"

# Get all Windows devices managed by Intune
$skuMapping = @{
    "2vCPU-4GB-64GB"  = @{  RAM = 4; Storage = 64 }
    "2vCPU-8GB-128GB" = @{  RAM = 8; Storage = 128 }
    "4vCPU-16GB-256GB" = @{ RAM = 16; Storage = 256 }
    "8vCPU-32GB-512GB" = @{ RAM = 32; Storage = 512 }
}

# Function to determine the best Windows 365 SKU
function Get-Windows365SKU {
    param ($ram, $storage)
    
    # Sort SKUs by RAM and Storage (ensuring we always pick the smallest SKU that meets/exceeds both)
    $sortedSkus = $skuMapping.GetEnumerator() | 
                  Sort-Object { $_.Value.RAM }, { $_.Value.Storage }
    
    foreach ($sku in $sortedSkus) {
        $specs = $sku.Value
        if ($ram -le $specs.RAM -and $storage -le $specs.Storage) {
            return $sku.Key
        }
    }
    
    return "Custom SKU Required"
}
# Process device data
$deviceReport = @()

foreach ($device in $devices.value) {
    $deviceID = $device.id
    $deviceName = $device.deviceName
    $osVersion = $device.operatingSystemVersion
    $primaryUser = $device.userPrincipalName

    # Fetch hardware details for each device
    $hardwareUri = "$deviceEndpoint/$deviceID"
    $hardwareDetails = Invoke-MgGraphRequest -Method Get -Uri "$($hardwareUri)?`$select=hardwareInformation"
    $memoryDetails = Invoke-MgGraphRequest -Method Get -Uri "$($hardwareUri)?`$select=hardwareInformation,physicalMemoryInBytes"

    $storage = $hardwareDetails.hardwareInformation.totalStorageSpace / 1GB
    $ram = $memoryDetails.physicalMemoryInBytes / 1GB

    # Determine recommended Windows 365 SKU
    $recommendedSKU = Get-Windows365SKU -ram $ram -storage $storage

    # Add device info to the report
    $deviceReport += [PSCustomObject]@{
        DeviceName      = $deviceName
        OSVersion      = $osVersion
        PrimaryUser    = $primaryUser
        RAM            = [math]::Round($ram, 2)
        Storage        = [math]::Round($storage, 2)
        RecommendedSKU = $recommendedSKU
    }
}

# Display the report as a table
$deviceReport | Format-Table -AutoSize

