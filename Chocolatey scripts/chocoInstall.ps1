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
Start-Transcript -Path "$($logPath)\$($app)_Install.log"

# Check for chocolatey and install
$choco = "C:\ProgramData\chocolatey"
Write-Host "Checking if Chocolatey is installed on $($env:COMPUTERNAME)..."

if(!(Test-Path $choco))
{
    Write-Host "Chocolatey was not found; installing now..."
    try 
    {
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        Write-Host "Chocolatey was successfully installed."    
    }
    catch 
    {
        $message = $_
        Write-Host "Error installing Chocolatey: $message"
    }
}
else 
{
    Write-Host "Chocolatey already installed."
}

# Check for app and install
Write-Host "Checking if $($app) is installed on $($env:COMPUTERNAME)..."
$installed = choco list | Select-String $app

if($installed -eq $null)
{
    Write-Host "$($app) was not found; installing now..."
    try 
    {
        Start-Process -Wait -FilePath "$($choco)\choco.exe" -ArgumentList "install $($app) -y"
        Write-Host "$($app) was successfully installed."    
    }
    catch 
    {
        $message = $_
        Write-Host "Error installing $($app): $message"
    }
}
else 
{
    Write-Host "$($app) is already installed."
}

Stop-Transcript