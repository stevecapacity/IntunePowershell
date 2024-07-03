New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS

$user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object Username).Username
$sid = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value

$userRegPath = "HKU\$($sid)\SOFTWARE"

# Prevent Teams from starting on login
reg.exe add "$($userRegPath)\Classes\LocalSettings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask" /v "State" /t DWORD /d 1 /f | Out-Host

# Set the detection flag
reg.exe add "HKLM\SOFTWARE\RubixDev" /v "teamsAutoStartDisabled" /t DWORD /d 1 /f | Out-Host
