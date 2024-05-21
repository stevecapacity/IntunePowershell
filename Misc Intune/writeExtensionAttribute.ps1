
# TENANT A CREDENTIALS
$clientId = "<CLIENTID>"
$clientSecret = "<CLIENTSECRET>"
$tenant = "<TENANTNAME>"

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")

$body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)

$response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body

#Get Token form OAuth.
$token = -join ("Bearer ", $response.access_token)

#Reinstantiate headers.
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)
$headers.Add("Content-Type", "application/json")
Write-Host "MS Graph Authenticated"

#============================================================#

# Get UserSID
$activeUsername = (Get-WmiObject Win32_ComputerSystem | Select-Object | username).username
$objUser = New-Object System.Security.Principal.NTAccount("$activeUsername")
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
$userSID = $strSID.Value

# Get full UPN
$regPath = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($userSID)\IdentityCache\$($userSID)"
$upn = Get-ItemPropertyValue -Path $regPath -Name UserName

$userObject = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Headers $headers

$attribute = $userObject.Value.extensionAttribute7

reg.exe add 'HKLM\SOFTWARE\IntuneMigration' /v ExtensionAttribute /t REG_SZ /d $attribute /f /reg:64 | Out-Host
