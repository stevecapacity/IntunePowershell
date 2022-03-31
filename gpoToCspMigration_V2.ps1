#Parameters
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$policyName,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$csvPath
)


#IMPORT REQUIRED MODULES



$requiredModules = @(
    'Microsoft.Graph.Intune'
)

$installedModules = Get-InstalledModule | Select-Object -ExpandProperty Name

foreach($module in $requiredModules)
{
    if($installedModules -contains $module)
    {
        Write-Host "$($module) is already installed"
    } else {
        Install-Module -Name $module -Scope CurrentUser
        Write-Host "$($module) not found.  Installing Now."
    }
}

foreach($module in $requiredModules)
{
    Import-Module $module
}

Connect-MSGraph -ForceInteractive


$policies = Import-Csv -Path $csvPath

$clean = @()
$cleanPolicies = @()

foreach($entry in $policies)
{
    $name = $entry.'Setting Name'
    $supported = $entry.'MDM Support'
    Write-Host $name
    if($clean.Contains($name) -or $supported -ne "Yes")
    {
        Write-Host "$($name) is a duplicate or unsupported item."
        continue
    }
    else
    {
        $clean += ($name)
        $cleanPolicies += $entry
    }
    
}



$oma = @()

foreach($policy in $cleanPolicies)
{
    
    $setting = $policy.'Setting Name' -replace '"',""
    $settingName = $setting.Trim()
    $value = $policy.Value.Trim('[',']') -replace '"', "'"
    $csp = $policy.'CSP Mapping'
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
        "displayName": "$policyName",
        "version": 1,
        "omaSettings": [
              $omaJson
        ]
        }
"@

        Invoke-MSGraphRequest -HttpMethod POST -Url "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -Content $body

    }

