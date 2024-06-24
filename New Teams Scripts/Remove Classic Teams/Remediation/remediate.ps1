# get all users
$allUsers = Get-ChildItem -Path "$($ENV:SystemDrive)\Users"

# uninstall Teams function
function Uninstall-ClassicTeams($teamsPath)
{
    Start-Process -FilePath "$($teamsPath)\Update.exe" -ArgumentList "--uninstall /s" -PassThru -Wait -ErrorAction Stop
}

# loop through all users
foreach($user in $allUsers)
{
    # Teams install paths
    $localAppData = "$($ENV:SystemDrive)\Users\$($user.Name)\AppData\Local\Microsoft\Teams"
    $programData = "$($ENV:SystemDrive)\$($user.Name)\Microsoft\Teams"

    # Check each install location and remove if found
    if (Test-Path $localAppData) 
    {
        Write-Output "Uninstall Teams classic for user $($user.Name)"
        Uninstall-ClassicTeams -teamsPath $localAppData
    }
    elseif (Test-Path $programData)
    {
        Write-Output "Uninstall Teams classic for user $($user.Name)"
        Uninstall-ClassicTeams -teamsPath $programData
    }
    else
    {
        Write-Output "Classic Teams not installed for user $($user.Name)"
    }
}

$oldFolder = "$($env:SystemDrive)\Users\*\AppData\Local\Microsoft\Teams"
$oldIcon = "$($env:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk"

Get-Item $oldFolder | Remove-Item -Recurse -Force
Get-Item $oldIcon | Remove-Item -Recurse -Force