# Import Graph module
#Import-Module Microsoft.Graph

# Connect with required scopes
#Connect-MgGraph -Scopes "DeviceManagementApps.Read.All","DeviceManagementConfiguration.Read.All","Group.Read.All"

$graph = "https://graph.microsoft.com/beta"

# Select Group
$groups = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/groups?`$select=id,displayName").value

$groupSelection = $groups | ForEach-Object {
    [PSCustomObject]@{
        Name    = $_.displayName
        Id      = $_.id
        Raw     = $_
    }
}

$selectedGroup = $groupSelection | ogv -Title "Select a group" -PassThru

if(-not $selectedGroup)
{
    Write-Host "No group selected."
    return
}

$groupId = $selectedGroup.id
Write-Host "`nSelected Group:`n$($selectedGroup.Name) ($groupId)`n" -ForegroundColor Cyan

# Helper function
function Get-AssignedItems
{
    param(
        [string]$url,
        [string]$type,
        [string]$nameField = "displayName"
    )

    $results = @()
    $items = Invoke-MgGraphRequest -Uri $url -Method GET

    foreach ($item in $items.value)
    {
        foreach ($assignment in $item.assignments)
        {
            if($assignment.target.groupId -eq $groupId)
            {
                $results += [PSCustomObject]@{
                    Type = $type
                    Name = $item.$nameField
                }
            }
        }
    }

    return $results
}

# Get assignments
$results = @()
$results += Get-AssignedItems -url "$graph/deviceAppManagement/mobileApps?`$expand=assignments" -type "app"
$results += Get-AssignedItems -url "$graph/deviceManagement/deviceConfigurations?`$expand=assignments" -type "Configuration Profiles"
$results += Get-AssignedItems -url "$graph/deviceManagement/configurationPolicies?`$expand=assignments" -type "Settings Catalog Policy" -nameField "name"

# Show results
if($results.Count -eq 0)
{
    Write-Host "No assignments found for this group."
}
else 
{
    $results | Sort-Object Type, Name | Format-Table Type, Name -AutoSize
}
