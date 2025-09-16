# Install Microsoft Graph module
if (-not (Get-PackageProvider -ListAvailable -Name nuget -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -Confirm:$false -Force
}

if (-not (Get-InstalledModule -Name Microsoft.Graph -ListAvailable -ErrorAction SilentlyContinue)) {
    Install-Module -Name Microsoft.Graph -Confirm:$false -Force
}

Import-Module Microsoft.Graph -Scope CurrentUser

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementScripts.ReadWrite.All"

# Create a directory to save scripts to
$scriptDirectory = "C:\IntuneScripts"
if(-not (Test-Path $scriptDirectory)) {
    New-Item -ItemType Directory -Path $scriptDirectory -Force
    Write-Output "Created directory: $scriptDirectory"
}

# Construct the graph call to get all scripts
$scriptsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$select=id,displayName,fileName"
$platformScripts = @()

do {
    $reponse = Invoke-MgGraphRequest -Method GET -Uri $scriptsUri
    $platformScripts += $reponse.value
    $scriptsUri = $response.'@odata.nextLink'
} while ($scriptsUri)


# Loop through each script to get and decode contents
foreach ($script in $platformScripts) {
    $scriptUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($script.id)?`$select=scriptContent"
    $scriptResponse = Invoke-MgGraphRequest -Method GET -Uri $scriptUri
    $decodedContent = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($scriptResponse.scriptContent))
    
    # Save to .ps1 file
    $filePath = Join-Path $scriptDirectory $($script.fileName)
    $decodedContent | Out-File -FilePath $filePath -Encoding UTF8

    Write-Output "Exported: $($script.displayName) to $filePath"
}


