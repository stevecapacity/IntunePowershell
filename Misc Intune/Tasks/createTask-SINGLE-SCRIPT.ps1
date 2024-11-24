$destination = "C:\ProgramData\Scripts"
if(!(Test-Path $destination))
{
	mkdir $destination
}

$scriptText = @"
$userName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName

$userName | Out-File "C:\ProgramData\Scripts\primaryUser.txt"
"@

New-Item -ItemType File -Path $destination -Name "userCheck.ps1"
$scriptText | Set-Content -Path "$destination\userCheck.ps1" -Force


$taskName = "Primary User Check"
$scriptPath = "C:\ProgramData\Scripts\userCheck.ps1"

$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Executionpolicy bypass -File `"$scriptPath`""
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevl Highest

Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Description "Run the Primary User Check Script at everylogon"

