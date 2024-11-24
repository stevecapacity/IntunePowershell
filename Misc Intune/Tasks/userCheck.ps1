$userName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName

$userName | Out-File "C:\ProgramData\Scripts\primaryUser.txt"