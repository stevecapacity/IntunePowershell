reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Host
reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" /v "LaunchOneDriveWithUser" /d "C:\Windows\LaunchOneDriveWithCurrentUser.cmd"
reg.exe unload HKLM\TempUser | Out-Host

$scriptText = "@echo off > nul
for /f `"delims=`" %%n in ('whoami/upn') do set upn=%%n

REM determine if Business1 instance is configured on this machine
reg.exe query HKCU\Software\Microsoft\OneDrive\Accounts\Business1 /v UserEmail > nul 2> nul
if errorlevel 1 goto :NotProvisioned
REM since OneDrive is provisioned already, dont run this script anymore
reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LaunchOneDriveWithUser /f
goto :EOF
:NotProvisioned
REM there was no Business1 UserEmail registry entry so launch OneDrive first run wizard with the logged in user ID
start odopen://sync?useremail=%upn%
"

New-Item -ItemType File -Path "C:\Windows" -Name "LaunchOneDriveWithCurrentUser.cmd" -Force
Add-Content -Path "C:\Windows\LaunchOneDriveWithCurrentUser.cmd" $scriptText | Set-Content "C:\Windows\LaunchOneDriveWithCurrentUser.cmd" -Force
Start-Sleep -Seconds 2