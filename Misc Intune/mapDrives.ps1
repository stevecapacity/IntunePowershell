# add an Intune detection rule
$path = "C:\ProgramData\Microsoft\DriveMapping"
if(!(Test-Path $path))
{
    mkdir $path
}
Set-Content -Path "$($path)\drivemapping.txt.tag" -Value "Installed"

# authenticate to graph
# user.read.all
# group.read.all
# groupmember.read.all
$clientId = "<CLIENT ID>"
$clientSecret = "<CLIENT SECRET>"
$domain = "<DOMAIN NAME>"

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")

$body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body += -join("&client_id=" , $clientId, "&client_secret=", $clientSecret)

$response = Invoke-RestMethod "https://login.microsoftonline.com/$($domain)/oauth2/v2.0/token" -Method 'POST' -Headers $header -Body $body
$token = -join("Bearer ", $response.access_token)

#Reinstantiate headers.
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)

# get the user sid
$user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object Username).Username
$sid = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).value

# get the group memberships
$upn = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($sid)\IdentityCache\$($sid)" -Name "UserName"
$groupMemberships = Invoke-RestMethod -Method Get -uri "https://graph.microsoft.com/beta/users/$($upn)/memberOf" -Headers $headers | Select-Object -ExpandProperty onPremisesSamAccountName

# loop through groups
$drives = @("@echo off")

foreach($group in $groupMemberships)
{
    if($group -eq "Group A")
    {
        $drives += "net use g: \\rbxdv-dc-01\share_a"
        break
    }
    elseif($group -eq "Group B")
    {
        $drives += "net use g: \\rbxdv-dc-01\share_b"
        break
    }
}

$drives2string = $drives | Out-String

# create desktop batch file to map
New-Item -ItemType File -Path "C:\Users\Public\Desktop" -Name "Map Drives.bat" -Force
Add-Content "C:\Users\Public\Desktop\Map Drives.bat" $drives2string | Set-Content "C:\Users\Public\Desktop\Map Drives.bat" -Force