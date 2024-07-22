# get device ID
$deviceId = ((Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Issuer -match "Microsoft Intune MDM Device CA"} | Select-Object Subject).Subject).TrimStart("CN=")

# assemble JSON payload
$payload = @{
    deviceId = $deviceId
} | ConvertTo-Json


$cutoffDate = ((Get-Date).AddDays(-30).ToString())
$currentRotationValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\BitLockerRotation" -Name "RotationDate"

if($null -eq $currentRotationValue -or $currentRotationValue -lt $cutoffDate)
{
    Write-Output "BitLocker recovery key was rotated more than 30 days ago. Attempting to rotate"
    reg.exe add "HKLM\SOFTWARE\BitLockerRotation" /v "RotationDate" /t REG_SZ /d (Get-Date).ToString() /f | Out-Host
    # send payload to webhook
    $webhook = ""
    Invoke-WebRequest -Uri $webhook -Method POST -Body $payload -UseBasicParsing
    Exit 1
}
else
{
    Write-Output "Bitlocker recovery key was rotated within 30 days.  No action needed."    
    Exit 0
}