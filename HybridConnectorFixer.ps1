# Setup
$WorkingDir = "$env:ProgramData\IntuneConnectorInstall"
$WebView2Installer = "$WorkingDir\MicrosoftEdgeWebView2Setup.exe"
$IntuneConnectorInstaller = "$WorkingDir\ODJConnectorBootstrapper.exe"
$IntuneConnectorProductName = "Intune Connector for Active Directory"
$RequiredConnectorVersion = "6.2505.0"
$RequiredDotNetRelease = 461808 # 4.7.2

# Make a working directory
if(-not(Test-Path $WorkingDir))
{
    mkdir $WorkingDir
}

# Check for WebView2
$WebView2Installed = Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like "*Microsoft Edge WebView2"}

if($WebView2Installed)
{
    Write-Host "Edge WebView2 already installed"
}
else
{
    Write-Host "Downloading and installing WebView2..."
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $WebView2Installer -UseBasicParsing
    Start-Process -FilePath $WebView2Installer -ArgumentList "/silent /install" -Wait
}

# Check for Net 4.7.2
try 
{
    $dotNetRelease = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction Stop
    if($dotNetRelease -lt $RequiredDotNetRelease)
    {
        Write-Warning ".NET Framework 4.7.2 or later is required. Detected Release: $dotNetRelase"
        Write-Warning "Please install .NET Framework 4.7.2 before continuing."
        exit 1
    }   
    else
    {   
        Write-Host ".NET Framework 4.7.2 or later is present."
    } 
}
catch 
{
    Write-Warning "Unable to detect .NET Framework. Please ensure 4.7.2 or later is installed."
    exit 1
}


# Check and uninstall previous Intune Connector

$IntuneConnector = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*$($IntuneConnectorProductName)*"} | Sort-Object DisplayVersion -Descending | Select-Object -First 1

if($IntuneConnector)
{
    Write-Host "Found connector: $($IntuneConnector.DisplayName) v$($IntuneConnector.DisplayVersion)"
    Write-Host "Uninstalling existing version..."

    if($IntuneConnector.UninstallString)
    {
        $uninstallCmd = $IntuneConnector.UninstallString -replace '"',''
        if($uninstallCmd -like "msiexec*")
        {
            Start-Process "msiexec.exe" -ArgumentList "/x", "$($IntuneConnector.PSChildName)", "/quiet", "/norestart" -Wait
        }
        else
        {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "$uninstallCmd /quiet /norestart" -Wait
        }
    }
}
else
{   
    Write-Host "Connector not installed."
}

# Install new connector
if(-not(Test-Path $IntuneConnectorInstaller))
{
    Write-Host "Downloading updated connector..."
    Invoke-WebRequest -Uri "https://download.microsoft.com/download/45476bf5-d8be-43a7-8e44-e76a4d1ab28f/ODJConnectorBootstrapper.exe" -OutFIle $IntuneConnectorInstaller -UseBasicParsing
}

Write-Host "Installing Intune Connector..."
Start-Process -FilePath $IntuneConnectorInstaller -Wait
