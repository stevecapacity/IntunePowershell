[cmdletbinding()]

param(
    [string]$WebhookData
)

## WebhookData

if($WebHookData)
{
    $bodyData = ConvertFrom-Json -InputObject $WebhookData.RequestBody
    $serialNumber = ((($bodyData.serialNumber) | Out-String).Trim())
    $manufacturer = ((($bodyData.manufacturer) | Out-String).Trim())
    $model = ((($bodyData.model) | Out-String).Trim())
}

Connect-MgGraph -Identity

$params = @{
    overwriteImportedDeviceIdentities = $false
	importedDeviceIdentities = @(
		@{
			importedDeviceIdentityType = "manufacturerModelSerial"
			importedDeviceIdentifier = "$($manufacturer),$($model),$($serialNumber)"
		}
	)
} | ConvertTo-Json

Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/importedDeviceIdentities/importDeviceIdentityList" -Body $params -ContentType "application/json"