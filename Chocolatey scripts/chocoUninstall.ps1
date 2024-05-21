# Parameters for app name and package name
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$app
)

<# Check for 64 bit powershell
if("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if(Test-Path "$($env:windir)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$($env:windir)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
        exit $LASTEXITCODE
    }
}#>

# make log path and start logging
$logPath = "C:\ProgramData\Microsoft\IntuneApps\$($app)"
if(!(Test-Path $logPath))
{
    mkdir $logPath
}
Start-Transcript -Path "$($logPath)\$($app)_Uninstall.log"

$choco = "C:\ProgramData\chocolatey"

# check for app and uninstall
Write-Host "Checking if $($app) is installed on $($env:COMPUTERNAME)..."
$installed = choco list | Select-String $app

if($installed -ne $null)
{
    Write-Host "$($app) is installed; uninstalling now..."
    try 
    {
        Start-Process -Wait -FilePath "$($choco)\choco.exe" -ArgumentList "uninstall $($app) -y"
        Write-Host "$($app) was successfully uninstalled."    
    }
    catch 
    {
        $message = $_
        Write-Host "Error uninstalling $($app): $message"
    }
}
else
{
    Write-Host "$($app) is no longer detected."
}

Stop-Transcript