#Query outdated apps into array
# Check for Chocolatey and install
$choco = "C:\ProgramData\chocolatey"
Write-Host "Checking if Chocolatey is installed on $($env:COMPUTERNAME)..."
if(!(Test-Path $choco))
{
    Write-Host "Chocolatey was not found; installing..."
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) 
    Write-Host "Chocolatey was successfully installed."
}
else
{
    Write-Host "Chocolatey already installed."
}

$outdated = choco outdated
$counter = 0
$apps = @()

foreach($x in $outdated)
{
    if($counter -lt 4)
    {   
        $counter += 1
        continue
    }
    if($x.Trim() -eq "")
    {
        break
    }
    $apps += $x.Split('|')[0]
}

#Attempt to update each app
if($apps -gt 0)
{
    foreach($app in $apps)
    {
        Write-Host "$($app) installed and out of date.  Attempting to update..."
        try
        {
            choco upgrade $app -y
            Write-Host "$($app) successfully updated to latest version."
        }
        catch
        {
            $message = $_
            Write-Host "Error updating $($app): $message"
        }
    }
}
else
{
    Write-Host "All apps are up to date"
}




