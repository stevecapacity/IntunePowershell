[cmdletbinding()]

param(
    [object]$WebhookData
)

## WebhookData

if($WebhookData)
{
    $bodyData = ConvertFrom-Json -InputObject $WebhookData.RequestBody
    $deviceId = ((($bodyData.deviceId) | Out-String).Trim())
}

Connect-MgGraph -Identity -Scopes BitlockerKey.Read.All

$recoveryKeys = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/informationProtection/bitlocker/recoveryKeys?`$filter=deviceId eq '$($deviceId)'")

$key = $recoveryKeys.value | Sort-Object -Property createdDateTime -Descending | Select-Object -First 1

$createdDateTime = $key.createdDateTime
$intuneDeviceObject = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$($deviceId)'").value

$intuneId = $intuneDeviceObject.id
$intuneName = $intuneDeviceObject.deviceName

$cutOffDate = (Get-Date).AddDays(-30)
Write-Output "Checking $($intuneName) for key rotation..."
if($createdDateTime -lt $cutOffDate)
{
    Write-Output "Recovery key for $($intuneName) was updated within the last 30 days, no need to rotate"
}
else
{
    Write-Output "Recovery key for $($intuneName) was not updated within the last 30 days, attempting to rotate..."
    try
    {
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($intuneId)/rotateBitlockerKeys"
        Write-Output "Successfully rotated key for $($intuneName)"
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Output "Failed to rotate key for $($intuneName): $message"
    }
}

