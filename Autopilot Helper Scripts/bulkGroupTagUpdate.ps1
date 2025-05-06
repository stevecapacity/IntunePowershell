
function Update-ModuleIfNeeded {
    param (
        [string]$moduleName
    )

    $module = Get-Module -ListAvailable -Name $moduleName -ErrorAction Ignore

    if (-not($module)) {
        Install-Module -Name $moduleName -Confirm:$false -Force -AllowClobber
        Write-Host "Installed $moduleName"
    } else {
        $installedVersion = (Get-Module -ListAvailable -Name $moduleName).Version
        $currentVersion = Find-Module -Name $moduleName | Select-Object -ExpandProperty Version

        if ($installedVersion -lt $currentVersion) {
            Update-Module -Name $moduleName -Confirm:$false -Force
            Write-Host "Updated $moduleName from version $installedVersion to $currentVersion"
        } else {
            Write-Host "$moduleName is up-to-date (version $installedVersion)"
        }
    }
    Write-Host "Loading module $moduleName $installedVersion)"
    Import-Module -Name $moduleName
}

# Example usage: Call the function with any module name
# Update-ModuleIfNeeded -moduleName "WindowsAutopilotIntune"

# install autopilot module
$nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction Ignore
if(-not($nuget))
{
    Install-PackageProvider -Name NuGet -confirm:$false -Force
    Write-Host "Installed NuGet"
}
else
{
    Write-Host "NuGet already installed"
}

$moduleName = "WindowsAutopilotIntune"
Update-ModuleIfNeeded -moduleName $moduleName

$moduleName = "Microsoft.Graph.Authentication"
Update-ModuleIfNeeded -moduleName $moduleName


# connect to microsoft graph
Connect-MgGraph

# You can change the group tag of autopilot devices using either a list of serial numbers or using an old group tag as a target

# OPTION 1: Change group tag using a list of serial numbers

<#
# get list of serial numbers from CSV file
$serialNumbers = Import-Csv -Path "C:\path\to\serialNumbers.csv" | Select-Object -ExpandProperty SerialNumber

# for each serial number, get entra device object id
foreach ($serialNumber in $serialNumbers) {
    try 
    {
        $id = (Get-AutopilotDevice -serial $serialNumber).id
        Set-AutopilotDevice -id $id -GroupTag "NewGroupTag"
        Write-Host "Changed group tag for device with serial number $serialNumber"        
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Failed to change group tag for device with serial number $($serialNumber): $message"
    }

}

#>

# OPTION 2: Change group tag using an old group tag as a target
$oldGroupTag = "DWVHN"
$newGroupTag = "VN-D"

# get list of devices with the old group tag
$devices = Get-AutopilotDevice | Where-Object {$_.GroupTag -eq "$oldGroupTag"}
foreach($device in $devices)
{
    try 
    {
        Set-AutopilotDevice -id $device.id -GroupTag $newGroupTag
        Write-Host "Changed group tag for device with serial number $($device.serialNumber)"        
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Failed to change group tag for device with serial number $($device.serialNumber): $message"
    }
}
