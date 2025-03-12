[string]$AutoPilotSettingsKey = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
[string]$DevicePrepName = 'DevicePreparationCategory.Status'
[string]$DeviceSetupName = 'DeviceSetupCategory.Status'
[bool]$DevicePrepNotRunning = $false
[bool]$DeviceSetupNotRunning = $false
        
$DevicePrepDetails = (Get-ItemProperty -Path $AutoPilotSettingsKey -Name $DevicePrepName -ErrorAction 'Ignore').$DevicePrepName
$DeviceSetupDetails = (Get-ItemProperty -Path $AutoPilotSettingsKey -Name $DeviceSetupName -ErrorAction 'Ignore').$DeviceSetupName
 
if (-not [string]::IsNullOrEmpty($DevicePrepDetails)) {
    $DeviceSetupDetails = $DeviceSetupDetails | ConvertFrom-Json
}
else {
    Write-Output "No_Autopilot_Config"
    Exit
}
 
 
if ($DeviceSetupDetails.categoryState -eq "inProgress") {
    Write-Output "ESP_Running"
    Exit
}
else {
    Write-Output "ESP_NotRunning"
    Exit
}
 
