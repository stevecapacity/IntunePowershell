# LOG FUNCTION
function log
{
    param(
        [string]$Message
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output = "$TimeStamp - $Message"
}

# START LOGGING
$LogFile = "$($env:PROGRAMDATA)\w365Backup.log"

if(!(Test-Path $LogFile))
{
    New-Item -Path $LogFile -ItemType File
}

Start-Transcript -Path $LogFile -Append -Verbose
log "Starting w365BACKUP script..."

# DEFINE AZURE SHARE DETAILS
$StorageAccountName = "<STORAGE ACCOUNT NAME>"
$StorageAccountKey = "<STORAGE ACCOUNT KEY>"
$SASToken = "<SAS TOKEN>"
$FileShare = "<FILESHARE NAME>"

# GET CURRENT USER SID (AS SYSTEM)
$CurrentUser = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName
$CurrentUserSID = (New-Object System.Security.Principal.NTAccount($CurrentUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
log "Current user: $($CurrentUser)"
log "Current user SID: $($CurrentUserSID)"

# INSTALL AZ.STORAGE POWERSHELL MODULE
log "Checking for Az.Storage module..."
if(-not(Get-Module -ListAvailable -Name Az.Storage -ErrorAction SilentlyContinue))
{
    log "Az.Storage module not found. Installing..."
    Install-Module -Name Az.Storage -Force -AllowClobber -Verbose
}
else 
{
    log "Az.Storage module found."
}

Import-Module Az.Storage


# SET THE STORAGE CONTEXT
log "Setting storage context..."
$StorageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
if(-not $StorageContext)
{  
    log "Failed to set storage context"
    Exit 1
}
else 
{
    log "Storage context is set"
}

# CHECK IF THE SHARE EXISTS
log "Checking for $($CurrentUserSID) directory in Azure File Share..."
$AzureShare = Get-AzStorageFile -ShareName $FileShare -Path $CurrentUserSID -Context $StorageContext -ErrorAction SilentlyContinue
if($null -eq $AzureShare)
{
    log "No backup found. Exiting..."
    Exit 1
}
else
{
    log "$($CurrentUserSID) directory found. Proceeding with migration."
}

# DOWNLOAD AZCOPY
# Check for AzCopy and download if missing
log "Checking for AzCopy..."
$AzCopyPath = "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
if (!(Test-Path $AzCopyPath)) {
    log "AzCopy not found. Downloading..."
    
    $AzCopyUrl = "https://aka.ms/downloadazcopy-v10-windows"
    $TempZipPath = "$env:TEMP\azcopy.zip"
    $ExtractPath = "$env:TEMP\azcopy"

    # Download AzCopy
    log "Downloading AzCopy from: $AzCopyUrl"
    try {
        Invoke-WebRequest -Uri $AzCopyUrl -OutFile $TempZipPath
        Expand-Archive -Path $TempZipPath -DestinationPath $ExtractPath -Force
        log "AzCopy downloaded and extracted to: $ExtractPath"    
    } catch {
        log "Failed to download AzCopy: $_"
        Exit 1
    }

    # Find AzCopy.exe
    $AzCopyExe = Get-ChildItem -Path $ExtractPath -Recurse -Filter "azcopy.exe" | Select-Object -First 1 -ExpandProperty FullName
    if ($AzCopyExe) {
        $AzCopyPath = $AzCopyExe
        log "AzCopy installed at: $AzCopyPath"
    } else {
        log "Error: AzCopy executable not found after extraction."
        Exit 1
    }
} else {
    log "AzCopy found at: $AzCopyPath"
}

# GET LOCAL LOCATIONS
$UserLocations = @()
$UserProfilePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($CurrentUserSID)").ProfileImagePath
$SourceFolders = @("Documents", "Downloads", "Desktop", "Pictures", "AppData")
foreach($Folder in $SourceFolders)
{
    $UserLocations += "$($UserProfilePath)\$($Folder)"
    log "Added $($UserProfilePath)\$($Folder) to backup list"
}

# RESTORE THE DATA FROM AZURE
log "Restoring user data..."
foreach($Location in $UserLocations)
{
    $FolderName = Split-Path $Location -Leaf
    $AzureSource = "https://$($StorageAccountName).file.core.windows.net/$($FileShareName)/$($CurrentUserSID)/$($FolderName)?$($SASToken)"

    log "Downloading $FolderName from Azure..."
    try 
    {
        Start-Process -Wait $AzCopyPath -ArgumentList "copy $($AzureSource) $($Location) --recursive=true"
        log "Restored $FolderName from Azure"    
    }
    catch 
    {
        log "Failed to restore $FolderName from Azure: $_"
    }
}

log "User data restore complete"
Stop-Transcript
