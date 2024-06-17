$msix = "$($PSScriptRoot)\MSTeams-x64.msix"
$destination = "C:\ProgramData\Microsoft\NEW-TEAMS-TEMP"
$exePath = "$($PSScriptRoot)\teamsbootstrapper.exe"

if(!(Test-Path $destination))
{
    mkdir $destination
}

Copy-Item -Path $msix -Destination $destination -Force

Start-Process -FilePath $exePath -ArgumentList "-p", "-o", "$($destination)\MSTeams-x64.msix" -Wait -WindowStyle Hidden