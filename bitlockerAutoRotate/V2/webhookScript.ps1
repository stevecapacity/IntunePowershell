# get the payload body
[cmdletbinding()]
param(
    [object]$WebhookData
)

if($WebhookData)
{
    $bodyData = ConvertFrom-Json -InputObject $WebhookData.RequestBody
    $deviceId = ((($bodyData.deviceId) | Out-String).Trim())
}

# connect to the graph
Connect-MgGraph -Identity

Write-Output "Recovery key for deviceId $($deviceId) was not updated within the last 30 days, attempting to rotate..."
try
{
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($deviceId)/rotateBitlockerKeys"
    Write-Output "Successfully rotated BitLocker key."
}
catch
{
    $message = $_.Exception.Message
    Write-Output "Failed to rotate BitLocker key: $message"
}
