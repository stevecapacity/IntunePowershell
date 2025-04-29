# Check for Firefox in 32 and 64 bit registry
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$firefoxInstalled = $false

foreach($path in $registryPaths)
{
    $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Firefox*" }
    if($apps)
    {
        $firefoxInstalled = $true
        break
    }
}

# Remediate if found
if($firefoxInstalled)
{
    Write-Output "Firefox is installed"
    exit 1
}
else
{
    Write-Output "Firefox is not installed"
    exit 0
}