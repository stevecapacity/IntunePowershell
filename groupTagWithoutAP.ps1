# This powershell script can apply a group tag to a device without Autopilot registration.

$clientID = "YOUR_CLIENT_ID"
$groupTag = "YOUR_GROUP_TAG"
$clientSecret = "YOUR_CLIENT SECRET"
$tenantName = "YOUR_TENANT_NAME.COM"

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")

$body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)

$response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body

#Get Token form OAuth.
$token = -join ("Bearer ", $response.access_token)

#Reinstantiate headers.
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)
$headers.Add("Content-Type", "application/json")

$entraDeviceId = ((Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match "MS-Organization-Access"} | Select-Object Subject).Subject).TrimStart("CN=")
$physicalIds = (Invoke-RestMethod GET -Uri "https://graph.microsoft.com/beta/devices/$($entraDeviceId)" -Headers $headers).physicalIds
$groupTag = "[OrderID]:$($groupTag)"
$physicalIds += $groupTag

$body = @{
    physicalIds = $physicalIds
} | ConvertTo-Json

Invoke-RestMethod -Method PATCH -Uri "https://graph.microsoft.com/beta/devices/$($entraDeviceId)" -Headers $headers -Body $body
