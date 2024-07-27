# Define your Azure AD app details
$clientId = "your-client-id"
$tenantId = "your-tenant-id"
$clientSecret = "your-client-secret"
$scope = "https://graph.microsoft.com/.default"

# Get the OAuth 2.0 token
$body = @{
    grant_type    = "client_credentials"
    scope         = $scope
    client_id     = $clientId
    client_secret = $clientSecret
}
$tokenResponse = Invoke-WebRequest -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body
$token = ($tokenResponse.Content | ConvertFrom-Json).access_token

# Function to get the last logged on user
function Get-LastLoggedOnUser($deviceId, $token) {
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get
    $deviceDetails = $response.Content | ConvertFrom-Json
    return $deviceDetails.userPrincipalName
}

# Function to get the primary user
function Get-PrimaryUser($deviceId, $token) {
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/users"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get
    $primaryUser = ($response.Content | ConvertFrom-Json).value | Where-Object { $_.isPrimaryUser -eq $true }
    return $primaryUser.userPrincipalName
}

# Function to update the primary user
function Update-PrimaryUser($deviceId, $newPrimaryUser, $token) {
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/assignUser"
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    $body = @{
        userPrincipalName = $newPrimaryUser
    } | ConvertTo-Json
    Invoke-WebRequest -Uri $uri -Headers $headers -Method Post -Body $body
    Write-Output "Updated primary user to $newPrimaryUser for device $deviceId"
}

# Get list of all managed devices
$uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
$headers = @{
    Authorization = "Bearer $token"
}
$response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get
$devices = ($response.Content | ConvertFrom-Json).value

foreach ($device in $devices) {
    $deviceId = $device.id
    $lastLoggedOnUser = Get-LastLoggedOnUser -deviceId $deviceId -token $token
    $primaryUser = Get-PrimaryUser -deviceId $deviceId -token $token

    if ($lastLoggedOnUser -ne $primaryUser) {
        Write-Output "Mismatch found for device $deviceId. Updating primary user from $primaryUser to $lastLoggedOnUser"
        Update-PrimaryUser -deviceId $deviceId -newPrimaryUser $lastLoggedOnUser -token $token
    } else {
        Write-Output "No mismatch for device $deviceId. Primary user: $primaryUser, Last logged on user: $lastLoggedOnUser"
    }
}
