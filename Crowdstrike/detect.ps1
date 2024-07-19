# Detecting the presence of the CrowdStrike driver on a system
# Thanks to Daniel Bleyer (https://www.linkedin.com/in/danielbleyer-uk/) for contributing the original version of this script
$driverFolder = "C:\Windows\System32\drivers\CrowdStrike"

if(Test-Path $driveFolder)
{
    $files = Get-ChildItem -Path $driverFolder -Recurse -Filter "*CD-00000291*.sys"
    if($files.Count -gt 0)
    {
        Write-Host "CrowdStrike driver found, removing..."
        exit 1
    }
    else
    {
        Write-Host "CrowdStrike driver not found, nothing to do."
        exit 0
    }
}
