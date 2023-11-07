function Install-ChocoPackage {
    [CmdletBinding()]
    Param(
        [parameter()]$appPackage,
        [parameter()]$appName
    )
    # Create local path for logging
    $logPath = "C:\ProgramData\Microsoft\IntuneApps\$($appName)"
    if(!(Test-Path $logPath))
    {
        mkdir $logPath
    }
    Start-Transcript -Path "$($logPath)\$($appName)Install.log" -Verbose

    # Check for Chocolatey and install
    $choco = "C:\ProgramData\chocolatey"
    Write-Host "Checking if Chocolatey is installed on $($env:COMPUTERNAME)..."
    if(!(Test-Path))
    {
        Write-Host "Chocolatey was not found; installing..."
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null
        Write-Host "Chocolatey was successfully installed."
    }
    else
    {
        Write-Host "Chocolatey already installed."
    }

    # Check if App exists
    $installed = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ | Get-ItemProperty | Select-Object DisplayName | Where-Object {$_.DisplayName -like "*$($appName)*"}

    # Install App
    if($installed -eq $null)
    {
        Write-Host "$($appName) was not found on $($env:COMPUTERNAME)- installing now..."
        Start-Process -Wait -FilePath "$($choco)\choco.exe" -ArgumentList "install $($appPackage) -y"
        Write-Host "$($appName) was successfully installed."
    }
    else
    {
        Write-Host "$($appName) is already installed."
    }
}
# Name app
$appName = ""
$appPackage = ""

# Run function
Install-ChocoPackage -appPackage $appPackage -appName $appName
