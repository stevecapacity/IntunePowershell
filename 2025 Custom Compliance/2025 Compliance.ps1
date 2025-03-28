# Check if Google Chrome is installed
$googleChrome = $false
if(Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe")
{
    $googleChrome = $true
}

# Check if DisableConsumerFeatures is enabled
$regKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$disableConsumerFeatureValue = $regKey.DisableWindowsConsumerFeatures

# Build the JSON table
$hash = @{
    ChromeInstalled = $googleChrome
    DisableConsumerFeatures = $disableConsumerFeatureValue
}

# return
return $hash | ConvertTo-Json -Compress