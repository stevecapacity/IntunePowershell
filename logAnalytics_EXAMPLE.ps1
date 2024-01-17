# Log analytics connection info

# workspace ID
$workspaceID = "<WORKSPACE ID>"
# primary key
$primaryKey = "<PRIMARY KEY>"

# create the object and array
$logObject = New-Object System.Object

$logInfo = @()

# add value to the object
$serialNumber = Get-WmiObject -Class Win32_Bios | Select-Object -ExpandProperty serialNumber
Write-Host "The serial number is $($serialNumber)"
$logInfo += @{Name="Serial Number";Value=$serialNumber}

$hostname = $env:COMPUTERNAME
Write-Host "The hostname is $($hostname)"
$logInfo += @{Name="Hostname";Value=$hostname}

$nuget = Get-PackageProvider -Name NuGet -ErrorAction Ignore
if(-not($nuget))
{
    Write-Host "NuGet not found installing now..."
    try {
        Install-PackageProvider -Name Nuget -Confirm:$false -Force
        Write-Host "NuGet installed successfully"
        $logInfo += @{Name="NuGet install status:";Value="SUCCESS"}
    }
    catch {
        $message = $_
        Write-Host "Error installing Nuget: $message"
        $logInfo += @{Name="NuGet install status:";Value="ERROR: $message"}
    }
}else {
    Write-Host "NuGet already installed"
    $logInfo += @{Name="NuGet install status:";Value="Already installed"}
}


# construct the JSON table
foreach($x in $logInfo)
{
    $logObject | Add-Member -MemberType NoteProperty -Name $x.Name -Value $x.Value
}

$json = $logObject | ConvertTo-Json

# post JSON to logs
$logType = "deviceInfoLogs"
$timeStampField = ""
Function Build-Signature ($workspaceID, $primaryKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($primaryKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $workspaceID,$encodedHash
    return $authorization
}

Function Post-LogAnalyticsData($workspaceID, $primaryKey, $body, $logType)
{
    $method = 'POST'
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [datetime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -workspaceID $workspaceID `
        -primaryKey $primaryKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $workspaceID + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $timeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}
    Post-LogAnalyticsData -workspaceID $workspaceID -primaryKey $primaryKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType



