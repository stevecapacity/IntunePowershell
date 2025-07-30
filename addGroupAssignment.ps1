$policyId = "<YOUR POLICY OBJECT ID>"
$targetGroup = "<YOUR GROUP OBJECT ID>"

$getUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($policyId)/assignments"
$postUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($policyId)/microsoft.graph.assign"

Connect-MgGraph

try {
    $assignments = Invoke-MgGraphRequest -Method GET -Uri $getUri    
}
catch {
    Write-Warning $_.Exception.Message
}

$groupAssignments = @($assignments.value | Where-Object { $_.target.'@odata.type' -eq "#microsoft.graph.groupAssignmentTarget" })

$alreadyAssigned = $groupAssignments | Where-Object { $_.target.groupId -eq $targetGroup }

if(-not $alreadyAssigned){
    $groupAssignments += [PSCustomObject]@{
        target = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            groupId = $targetGroup
        }
    }
}

$body = @{
    assignments = $groupAssignments | ForEach-Object {
        @{
            target = @{
                "@odata.type" = $_.target.'@odata.type'
                groupId = $_.target.groupId
            }
        }
    }
} | ConvertTo-Json -Depth 10

try {
    Invoke-MgGraphRequest -Method POST -Uri $postUri -Body $body -ContentType "application/json"
}
catch {
    Write-Warning $_.Exception.Message
}
