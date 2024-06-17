$TeamsApp = Get-AppxPackage "*Teams*" -AllUsers -ErrorAction SilentlyContinue
if($TeamsApp.Name -eq "MicrosoftTeams")
{
    Write-Host "Built-in Teams App found"
    Exit 1
}
else
{
    Write-Host "Built-in Teams App found"
    Exit 0
}