function Uninstall-TeamsClassic($teamsPath)
{
    try
    {
        $process = Start-Process -FilePath "$($teamsPath)\Update.exe" -ArgumentList "--uninstall /s" -PassThru -Wait -ErrorAction Stop
        if($process.ExitCode -ne 0)
        {
            $message = $_.Exception.Message
            Write-Host "Error uninstalling Classic Teams Client: $message"
        }
    }
    catch
    {
        $message = $_.Exception.Message
    }
}


$registryPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

$MachineWide = Get-ItemProperty -Path $registryPath | Where-Object {$_.DisplayName -eq "Teams Machine-Wide Installer"}

if($MachineWide)
{
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/x ""$($MachineWide.PSChildName)"" /qn" -NoNewWindow -Wait
}
else
{
    Write-Host "Teams Classic (Machine-Wide installer) not found"
}

$AllUsers = Get-ChildItem -Path "$($ENV:SystemDrive)\Users"

foreach($user in $AllUsers)
{
    Write-Host "Processing user: $($user.Name)"
    $localAppData = "$($ENV:SystemDrive)\Users\$($user.name)\AppData\Local\Microsoft\Teams"
    $programData = "$($ENV:ProgramData)\$($User.Name)\Microsoft\Teams"

    if(Test-Path "$localAppdata\Current\Teams.exe")
    {
        Write-Host "Uninstall Teams for user $($user.Name)"
        Uninstall-TeamsClassic -teamsPath $localAppData
    }
    elseif(Test-Path "$programData\Current\Teams.exe")
    {
        Write-Host "Uninstall Teams for user $($user.Name)"
        Uninstall-TeamsClassic -teamsPath $programData
    }
    else
    {
        Write-Host "Teams classic not found for user $($user.Name)"
    }
}

$TeamsFolder_old = "$($ENV:SystemDrive)\Users\*\AppData\Local\Microsoft\Teams"
$TeamsIcon_old = "$($ENV:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk"
Get-Item $TeamsFolder_old | Remove-Item -Force -Recurse
Get-Item $TeamsIcon_old | Remove-Item -Force Recurse

