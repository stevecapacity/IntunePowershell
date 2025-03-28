# Find the Intune enrollment registry path
$ErrorActionPreference = "SilentlyContinue"

$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
$enrollments = Get-ChildItem -Path $enrollmentPath
foreach($enrollment in $enrollments)
{
    $object = Get-ItemProperty Registry::$enrollment
    $enrollPath = Join-Path -Path $enrollmentPath -ChildPath $object.PSChildName
    $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL"
    if($key)
    {
        $regPath = "$($enrollPath)\DeviceEnroller"
        break
    }
    else
    {
        Write-Host "Not enrolled"
    }
}

# get enrolled date and time
$firstSessionBinary = Get-ItemProperty -Path $regPath -Name "FirstSessionTimestamp" -ErrorAction SilentlyContinue

function convertFromBinary($binary)
{
    if($binary)
    {
        $fileTime = [System.BitConverter]::ToInt64($binary, 0)
        return [datetime]::FromFileTimeUtc($fileTime)
    }
    return "Not Found"
}

$firstSessionTime = convertFromBinary($firstSessionBinary.FirstSessionTimestamp)

$currentTime = Get-Date

$timeDifference = $currentTime - $firstSessionTime

if($timeDifference.TotalHours -lt 3)
{
    Write-Output "Install"
}
else
{
    Write-Output "Dont Install"
}