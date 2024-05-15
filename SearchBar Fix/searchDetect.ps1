$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$name = "SearchOnTaskbarMode"

$currentSetting = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue

if($currentSetting -ne 1)
{
    Write-Host "Search box not set to 1"
    Exit 1
}
else
{
    Write-Host "Search box is already set to 1"
    Exit 0
}