function Uninstall-ChocoPackage {
    [CmdletBinding()]
    Param(
        [parameter()]$appPackage,
        [parameter()]$appName
    )

    $logPath = "C:\ProgramData\Microsoft\IntuneApps\$($appName)"
    Start-Transcript -Path "$($logPath)\$($appName)Uninstall.log" -verbose

    # Check if App exists
    $installed = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ | Get-ItemProperty | Select-Object DisplayName | Where-Object {$_.DisplayName -like "*$($appName)*"}

    if($installed -ne $null)
    {
        Write-Host "$($appName) is installed on $($env:COMPUTERNAME).  Uninstalling now..."
        Start-Process -Wait -FilePath "C:\ProgramData\chocolatey\choco.exe" -ArgumentList "uninstall $($appPackage) -y"
        Write-Host "$($appName) was successfully uninstalled."
    }
    else
    {
        Write-Host "$($appName) is not installed on $($env:COMPUTERNAME)."
    }
}

$appName = ""
$appPackage = ""

Uninstall-ChocoPackage -appPackage $appPackage -appName $appName
