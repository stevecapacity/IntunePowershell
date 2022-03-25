##############################################
Microsoft Graph Authentication
##############################################

#Function to properly search all graph results
function Get-GraphPagedResult
{
    param ([parameter(Mandatory = $true)]$Headers,[parameter(Mandatory = $true)]$Uri,[Parameter(Mandatory=$false)][switch]$Verb)
    $amalgam = @()
    $pages = 0
    do
    {
        $results = Invoke-RestMethod $Uri -Method "GET" -Headers $Headers
        if ($results.value)
            {$amalgam += $results.value}
        else
            {$amalgam += $results}
        $pages += 1

        if($Verb)
        {Write-Host "Completed page $pages for url $Uri"}

        $Uri = $results.'@odata.nextlink'

    } until (!($Uri))

    $amalgam
}


#App registration
#******************************************************#
$tenant = "<YOUR TENANT NAME>"
$clientId = "<CLIENT / APPLICATION ID>"
$clientSecret = "<CLIENT SECRET>"
#******************************************************#


#Header and body request variables
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")
$body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body += -join("&client_id=" , $clientId, "&client_secret=", $clientSecret)
$response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $header -Body $body
$token = -join("Bearer ", $response.access_token)
#Reinstantiate headers
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)
$headers.Add("Content-Type", "application/json")
###############################################################################################
## END AUTH ###
###############################################################################################

$csvPath = "<THE PATH TO YOUR GPO.CSV EXPORT>"

$policies = Import-Csv -Path $csvPath

$oma = @()

foreach($policy in $policies)
{
    
    $setting = $policy.SettingName -replace '"',""
    $settingName = $setting.Trim()
    $value = $policy.Value.Trim('[',']') -replace '"', "'"
    $csp = $policy.csp
    Write-Host "Migrating policy $($settingName): CSP setting is $($csp) with value: $($value)"
    $setValue = ""
    [string]$InString = $value
    [Int32]$OutNumber = $null
    if($value -eq ""){
        Write-Host "Value is null.  Cannot proceed"
        continue
    } else {       
    if ($value -eq "ENABLED")

    {
        $setValue = "</enabled>"
        $odataType = "#microsoft.graph.omaSettingString"
         $omaSetting = @"
    {
        "@odata.type" : "$odataType",
        "displayName" :"$settingName",
        "description" : "",
        "omaUri" : "$csp",
        "value" : "$setValue"
        },
"@
    
        $oma += $omaSetting
        $count += 1
        continue
    } elseif ($value -eq "DISABLED")
    {
        $setValue = "</disabled>"
        $odataType = "#microsoft.graph.omaSettingString"
         $omaSetting = @"
    {
        "@odata.type" : "$odataType",
        "displayName" :"$settingName",
        "description" : "",
        "omaUri" : "$csp",
        "value" : "$setValue"
        }
"@
    
        $oma += $omaSetting
        $count += 1
        continue
    } elseif ($value -eq "TRUE"){
        $setValue = $true
        $odataType ="#microsoft.graph.omaSettingBoolean"
         $omaSetting = @"
    {
        "@odata.type" : "$odataType",
        "displayName" :"$settingName",
        "description" : "",
        "omaUri" : "$csp",
        "value" : "$setValue"
        }
"@
    
        $oma += $omaSetting
        $count += 1
        
    } elseif ($value -eq "FALSE"){
        $setValue = $false
        $odataType ="#microsoft.graph.omaSettingBoolean"
         $omaSetting = @"
    {
        "@odata.type" : "$odataType",
        "displayName" :"$settingName",
        "description" : "",
        "omaUri" : "$csp",
        "value" : "$setValue"
        }
"@
    
        $oma += $omaSetting
        $count += 1
        continue
    } elseif ([Int32]::TryParse($InString,[ref]$OutNumber))
    {
        $setValue = $value
        $odataType = "#microsoft.graph.omaSettingInteger"
         $omaSetting = @"
    {
        "@odata.type" : "$odataType",
        "displayName" :"$settingName",
        "description" : "",
        "omaUri" : "$csp",
        "value" : $setValue
        }
"@
    
        $oma += $omaSetting
        $count += 1
        continue
    } else {
        $setValue = $value
        $setValue = $setValue.Replace('\','\\')
        $odataType = "#microsoft.graph.omaSettingString"
         $omaSetting = @"
    {
        "@odata.type" : "$odataType",
        "displayName" :"$settingName",
        "description" : "",
        "omaUri" : "$csp",
        "value" : "$setValue"
        }
"@
    
        $oma += $omaSetting
        $count += 1
        continue   
    }
}
   
    
    
      
         #Write-Host "Policy $($settingName) has a value of $($setValue).  The odata-type is $($odataType)"
}

$omaJson = $oma -join ","
$omaJson = $omaJson -replace ",,",","

if($null -ne $omaJson){

    
   $body = @"
    {
        "@odata.type" : "#microsoft.graph.windows10CustomConfiguration",
        "description": "",
        "displayName": "GPO CSP Policy",
        "version": 1,
        "omaSettings": [
              $omaJson
        ]
        }
"@

        Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -Method POST -Headers $headers -body $body

    }
