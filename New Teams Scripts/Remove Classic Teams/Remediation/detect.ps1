# Registry path for teams machine wide installer
$registryPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

# Check if uninstall string is in registry
$classicTeams = Get-ItemProperty -Path $registryPath | Where-Object {$_.DisplayName -eq "Teams Machine-Wide Installer"}

# Check if exists
if($classicTeams)
{
    # trigger remediation
    Write-Output "Classic Teams found; attempting uninstall"
    Exit 1
}
else
{
    Write-Output "Classic Teams not found."
    Exit 0
}
