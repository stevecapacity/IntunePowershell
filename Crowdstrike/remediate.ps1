# Remediate CrowdStrike driver file on a system
# Thanks to Daniel Bleyer (https://www.linkedin.com/in/danielbleyer-uk/) for contributing the original version of this script

#Define the CrowdStrike Driver Folder

$driverFolder = "C:\Windows\System32\drivers\CrowdStrike"

 if(Test-Path $driverFolder) 
 {
    $files = Get-ChildItem -Path $driverFolder -Recurse -Filter "*CD-00000291*.sys" 
    foreach($file in $files)
    {
        # get last write time
        $UTCwriteTime = $file.LastWriteTimeUtc

        # Check last LastWriteTimeUTC matches issue
        if($UTCwriteTime.Hour -eq 4 -and $UTCwriteTime.minute -eq 9)
        {
            Write-Output "CrowdStrike file found, removing..."
            Remove-Item -Path $file.FullName -Force
        }
        else
        {
            Write-Output "CrowdStrike file found, but not the problem version, nothing to do."
        }        
    }
}