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
$StorageAccountName = "rubixcloudpc"
$StorageAccountKey = "Ltm04ZwBSkJX+NnnSBajfk5YEQZEY3oLUYLCzxd2OoFTT7irZ0kp8p7/C0xm5VDP7sn7hb9oO8q7+AStcEPdvg=="
$SASToken = "sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacupiytfx&se=2026-03-12T02:31:50Z&st=2025-03-11T18:31:50Z&spr=https&sig=ltS%2Bds%2BYh%2BAkZUzH8XDH3c2JKC%2F5qh%2BZHGBRRoK0YXs%3D"
$FileShare = "w365"

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

# CHECK FOR AZURE DIRECTORY (SID)
log "Checking for existing SID folder in Azure Storage..."
$AzureShare = Get-AzStorageFile -ShareName $FileShare -Path $CurrentUserSID -Context $StorageContext -ErrorAction SilentlyContinue
if($null -eq $AzureShare)
{
    log "Folder not found. Creating..."
    New-AzStorageDirectory -ShareName $FileShare -Path $CurrentUserSID -Context $StorageContext
    log "Folder created"
}
else
{
    log "Folder exists"
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

# DOWNLOAD AZCOPY
log "Checking for AzCopy..."
$AzCopyPath = "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
if(!(Test-Path $AzCopyPath))
{
    log "AzCopy not found. Downloading..."

    $AzCopyUrl = "https://aka.ms/downloadazcopy-v10-windows"
    $TempZipPath = "$($env:TEMP)\azcopy.zip"
    $ExtractPath = "$($env:TEMP)\azcopy"

    try 
    {
        Invoke-WebRequest -Uri $AzCopyUrl -OutFile $TempZipPath
        Expand-Archive -Path $TempZipPath -DestinationPath $ExtractPath -Force
        log "AzCopy downloaded and extracted to $($ExtractPath)"    
    }
    catch 
    {
        log "Failed to download AzCopy: $_"
        Exit 1
    }

    $AzCopyExe = Get-ChildItem -Path $ExtractPath -Recurse -Filter "azcopy.exe" | Select-Object -First 1 -ExpandProperty FullName
    if($AzCopyExe)
    {
        $AzCopyPath = $AzCopyExe
        log "AzCopy is installed at: $($AzCopyPath)"
    }
    else
    {
        log "Error: AzCopy executable not found after extraction."
        Exit 1
    }
}
else
{
    log "AzCopy found at: $AzCopyPath"
}

# BACKUP DATA TO AZURE
log "Backing up user data to Azure..."
$DestinationPath = "https://$($StorageAccountName).file.core.windows.net/$($FileShare)/$($CurrentUserSID)?$($SASToken)"
foreach($Location in $UserLocations)
{
    log "Copying $Location to Azure"
    try 
    {
        Start-Process -Wait $AzCopyPath -ArgumentList "copy $($Location) $($DestinationPath) --recursive=true"
        log "Copied $Location to Azure file share successfully"    
    }
    catch 
    {
        log "Filed to copy $Location to Azure File Share: $_"
    }
}

log "User data backup complete."
# STOP LOGGING
Stop-Transcript
