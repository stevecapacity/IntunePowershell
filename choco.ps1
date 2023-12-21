#Parameters for app name
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$app,
    [Parameter(Mandatory=$False,Position=2)]
    [switch]$uninstall = $False
)

#Start logging
$logPath = "C:\ProgramData\Microsoft\IntuneApps\$($app)"
if(!(Test-Path $logPath))
{
    mkdir $logPath
}
Start-Transcript -Path "$($logPath)\$($app)_Install.log" -Verbose

#Check if chocolatey is installed
$choco = "C:\ProgramData\chocolatey"
Write-Host "Checking if Chocolatey is installed on $($env:COMPUTERNAME)..."
if(!(Test-Path $choco))
{
    Write-Host "Chocolatey not found; installing now..."
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
    Write-Host "Chocolatey is installed."
}

$installed = choco list | Select-String $app
$installFlag = "$($logPath)\$($app)_installed.txt"

#Check for app and install
if($uninstall -eq $False)
{
    Write-Host "Running choco-install"

    Write-Host "Checking if $($app) is installed on $($env:COMPUTERNAME)..."
    if($installed -eq $null)
    {
        Write-Host "$($app) not detected; installing now..."
        Start-Process -Wait -FilePath "$($choco)\choco.exe" -ArgumentList "install $($app) -y"
        if($LASTEXITCODE -ne 0)
        {
            $message = $_
            Write-Host "Error installing $($app): $message"
            exit 1
        }
        else 
        {
            Write-Host "$($app) installed successfully"
            $installFlag = "$($logPath)\$($app)_installed.txt"
            New-Item $installFlag -Force
        }
    }
    else
    {
        Write-Host "$($app) already installed.  Updating to latest version..."
        Start-Process -Wait -FilePath "$($choco)\choco.exe" -ArgumentList "upgrade $($app) -y"
        if($LASTEXITCODE -ne 0)
        {
            $message = $_
            Write-Host "Error installing $($app): $message"
            exit 1
        }
        else 
        {
            Write-Host "$($app) updated successfully"
            New-Item $installFlag -Force
        }
    }
}
else 
{
    Write-Host "Running choco-uninstall"
    if($installed -ne $null)
    {
        Write-Host "$($app) detected; uninstalling now..."
        Start-Process -Wait -FilePath "$($choco)\choco.exe" -ArgumentList "uninstall $($app) -y"
        if($LASTEXITCODE -ne 0)
        {
            $message = $_
            Write-Host "Error uninstalling $($app): $message"
            exit 1
        }
        else 
        {
            Write-Host "$($app) successfully uninstalled"
            Remove-Item $installFlag -Force
        }
    }
    else 
    {
       Write-Host "$($app) not detected"
    }
}

Stop-Transcript
