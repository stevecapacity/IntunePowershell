$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-executionpolicy bypass -command "reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f | Out-Host"'

$Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" #Warning: the admin Group name is localised

Register-ScheduledTask -TaskName 'uninstallChat' -Action $action -Principal $Principal

$svc = New-Object -ComObject 'Schedule.Service'
$svc.Connect()

$user = 'NT SERVICE\TrustedInstaller'
$folder = $svc.GetFolder('\')
$task = $folder.GetTask('uninstallChat')

#Start Task
$task.RunEx($null, 0, 0, $user)

Start-Sleep -Seconds 5

#Kill Task
$task.Stop(0)

#remove task From Task Scheduler
Unregister-ScheduledTask -TaskName 'uninstallChat' -Confirm:$false
