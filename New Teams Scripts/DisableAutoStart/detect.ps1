$detectionFlag = (Get-ItemProperty -Path "HKLM:\SOFTWARE\RubixDev" -Name "teamsAutoStartDisabled").teamsAutoStartDisabled

if ($detectionFlag -eq 1) {
    Write-Output "Setting already applied."
    Exit 0
} else {
    Write-Output "Setting not applied."
    Exit 1
}