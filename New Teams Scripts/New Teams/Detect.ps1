$path = "C:\Program Files\WindowsApps"

$newTeams = Get-ChildItem -Path $path -Filter "MSTeams_*"

if($newTeams)
{
    Write-Host "New Teams is installed"
    exit 0
}
else
{
    Write-Host "New Teams not found"
    exit 1
}

