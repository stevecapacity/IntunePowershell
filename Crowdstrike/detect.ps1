# Detecting the presence of the CrowdStrike driver on a system
# Thanks to Daniel Bleyer (https://www.linkedin.com/in/danielbleyer-uk/) for contributing the original version of this script
$driverFolder = "C:\Windows\System32\drivers\CrowdStrike"

if(Test-Path $driveFolder)
{
    $files = Get-ChildItem -Path $driverFolder -Recurse -Filter "*CD-00000291*.sys"
    foreach($file in $files)
    {
        $UTCwriteTime = $file.LastWriteTimeUtc
        if($UTCwriteTime.Hour -eq 4 -and $UTCwriteTime.minute -eq 9)
        {
            Write-Host "CrowdStrike driver found, removing..."
            exit 1
        }
        else
        {
            Write-Host "CrowdStrike driver found, but not the problem version, nothing to do."
            exit 0
        }
    }
}
