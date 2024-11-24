$destination = "C:\ProgramData\Scripts"
if(!(Test-Path $Destination)
{
	mkdir $Destination
}

Copy-Item -Path "$($psscriptroot)\userCheck.ps1" -Destination $Destination -Recurse -Force

schtasks.exe /create /xml "$($psscriptroot)\Primary User Check.xml" /tn "Primary User Check" /f | Out-Host