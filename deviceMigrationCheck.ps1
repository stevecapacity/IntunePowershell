# GET DEVICE INFO
$serialNumber = Get-WmiObject -Class Win32_Bios | Select -ExpandProperty serialNumber
$hostname = $env:COMPUTERNAME
$OSVersion = ([System.Environment]::OSVersion.Version).Build

# GET DISK INFO
$diskInfo = Get-Volume -DriveLetter C
$totalDiskSize = "{0:N2} GB" -f ($diskInfo.Size/ 1Gb)
$freeDiskSpace = "{0:N2} GB" -f ($diskInfo.SizeRemaining/ 1Gb)
$memory = "{0:N2} GB" -f ((Get-CimInstance win32_PhysicalMemory | Measure-Object Capacity -Sum).sum /1gb)


# GET INSTALLED APPLICATIONS

$allApps = @()

$UninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

$appReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME)
$appRegKey = $appReg.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
$subKeys = $appRegKey.GetSubKeyNames()

foreach($key in $subKeys)
{
    $thisKey = $UninstallKey+"\\"+$key
    $thisSubKey = $appReg.OpenSubKey($thisKey)

    $app = $thisSubKey.GetValue("DisplayName")

    if($app -ne $null)
    {
        $allApps += "<Application>$app</Application>`n"
    }
}

# CHECK MAPPED DRIVES
$allDrives = @()

$activeUsername = (Get-WmiObject Win32_ComputerSystem | Select-Object username).username
$user = $activeUsername -replace '.*\\'
$objUser = New-Object System.Security.Principal.NTAccount("$activeUsername")
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
$activeUserSID = $strSID.Value

$HKU = Get-PSDrive | Where-Object {$_.Name -eq "HKU"}
if(-not($HKU))
{
    Write-Host "HKU not loaded.  Adding..."
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
}
else
{
    Write-Host "HKU exists"
}

$drives = Get-ItemProperty -Path "HKU:\$activeUserSID\Network\*" | Select-Object pschildname,remotepath

foreach($drive in $drives)
{
    $driveLetter = $drive | Select-Object -ExpandProperty pschildname
    $drivePath = $drive | Select-Object -ExpandProperty remotepath
    $driveXML = "<Drive>`n<DriveLetter>$driveLetter</DriveLetter>`n<DrivePath>$drivePath</DrivePath>`n</Drive>`n"
    $allDrives += $driveXML
}

# GET CONNECTED PRINTERS
$allPrinters = @()

$printers = Get-Printer

foreach($printer in $printers)
{
    $Name = $printer | Select-Object -ExpandProperty Name
    $Driver = $printer | Select-Object -ExpandProperty DriverName
    $Port = $printer | Select-Object -ExpandProperty PortName
    $xmlPrinter = "<Printer>`n<Name>$Name</Name>`n<Driver>$Driver</Driver>`n<Port>$Port</Port>`n</Printer>`n"
    $allPrinters += $xmlPrinter
}

# CHECK OS BUILD FOR MIRATION STATUS
$STATUS = ""

if($OSVersion -ge "19045")
{
    Write-Host "Windows version $($OSVersion) meets the requirement for migration"
    $STATUS = "PASS"
} else 
{
    Write-Host "Windows version $($OSVersion) does not meet the requirement for migration"
    $STATUS = "FAIL"
}

# CONSTRUCT XML

$xmlString = @"
<Config>
<Hostname>$hostname</Hostname>
<SerialNumber>$serialNumber</SerialNumber>
<OSVersion></OSVersion>
<InstalledMemory>$memory</InstalledMemory>
<Disk>
<TotalStorage>$totalDiskSize</TotalStorage>
<FreeStorage>$freeDiskSpace</FreeStorage>
</Disk>
<Applications>
$allApps</Applications>
<MappedDrives>
$allDrives</MappedDrives>
<Printers>
$allPrinters</Printers>
</Config>
"@

# INSTALL AZ STORAGE MODULE FOR BLOB
$nuget = Get-PackageProvider -Name NuGet

if(-not($nuget))
{
    Write-Host "Package Provider NuGet not found - installing now..."
    Install-PackageProvider -Name NuGet -Confirm:$false -Force
} else 
{
    Write-Host "Package Provider NuGet already installed."
}

$azStorage = Get-InstalledModule -Name Az.Storage

if(-not($azStorage))
{
    Write-Host "Az.Storage module not found - installing now..."
    Install-Module -Name Az.Storage -Force
    Import-Module Az.Storage
} else 
{
    Write-Host "Az.Storage module already installed."
}


# CONNECT TO BLOB STORAGE
$storageAccountName = "<STORAGE ACCOUNT NAME>"
$storageAccountKey = "<STORAGE ACCOUNT KEY>"
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
$container = "<CONTAINER NAME>"

# EXPORT XML FILE TO BLOB STORAGE
$path = "C:\ProgramData\IntuneMigration\"
if(!(Test-Path $path))
{
    mkdir $path
}
$filePath = "$($path)\$($hostname)-$($user)-$($STATUS).xml"
$xmlString | Out-File -FilePath $filePath
$blobName = $hostname + "-" + $user + "-" + $STATUS + ".xml"
Set-AzStorageBlobContent -File $filePath -Container $container -Blob $blobName -Context $context -Force
