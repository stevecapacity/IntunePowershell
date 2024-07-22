# get device ID and look up bitlocker recovery key in Entra
$deviceId = ((Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Issuer -match "MS-Organization-Access"} | Select-Object Subject).Subject).TrimStart("CN=")

# assemble payload
$payload = @{
    deviceId = $deviceId
} | ConvertTo-Json

# send request to webhook
$webhook = ""
Invoke-WebRequest -Uri $webhook -Method POST -Body $payload -UseBasicParsing



