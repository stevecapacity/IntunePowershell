# Prompt for Hyper-V VM name, Windows version, and CPU count
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$VMname,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$version,

    [Parameter(Mandatory=$True,Position=3)]
    [string]$CPUCount
)

# log function
function log()
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$message
    )
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$date - $message"
}

# set drive volumes and paths

# set volume below
$volume = "" # for example, $volume = "D:"

# Check for paths
$templates = "$($volume)\Templates"
$virtualMachines = "$($volume)\Hyper-V\Virtual machines"
$virtualHardDisks = "$($volume)\Hyper-V\Virtual hard disks"

log "Checking for $virtualMachines..."
if(!(Test-Path $virtualMachines))
{
    log "Creating directory $virtualMachines"
    try
    {
        mkdir $virtualMachines
        log "Directory $virtualMachines created"
    }
    catch
    {
        log "Failed to create directory $virtualMachines"
        log "Error: $_"
        exit 1
    }
}
else
{
    log "Directory $virtualMachines already exists"
}

log "Checking for $virtualHardDisks..."
if(!(Test-Path $virtualHardDisks))
{
    log "Creating directory $virtualHardDisks"
    try
    {
        mkdir $virtualHardDisks
        log "Directory $virtualHardDisks created"
    }
    catch
    {
        log "Failed to create directory $virtualHardDisks"
        log "Error: $_"
        exit 1
    }
}
else
{
    log "Directory $virtualHardDisks already exists"
}

# generate random TEMP number
log "Generating random number..."
$number = Get-Random -Minimum 1000 -Maximum 10000
$numberString = $number.ToString()
log "Random number: $numberString"

# get date
log "Getting date..."
$date = Get-Date -Format "MM-dd"
log "Date: $date"

# Set TEMP VM name
log "Setting VM name..."
$VMName = $VMname + "-" + $date + "-" + $numberString
log "Temporarily setting VM name to $VMName"

# Copy the gold master image to the Hyper-V directory with the VM name
log "Copying $version disk from $templates..."
try 
{
    Copy-Item -Path "$($templates)\GM-$($version).vhdx" -Destination "$($virtualHardDisks)\$($VMName).vhdx" -Force | Out-Null
    log "Disk copied to $virtualHardDisks"
}
catch 
{
    log "Failed to copy disk to $virtualHardDisks"
    log "Error: $_"
    exit 1
}

# define network and VM storage path
$VMSwitchName = "" # for example, $VMSwitchName = "Default Switch"
log "Setting VM switch name to $VMSwitchName"

$VhdxPath = "$($virtualHardDisks)\$($VMName).vhdx"
log "Setting VHD path to $VhdxPath"

# Set VM paramters
New-VM -Name $VMname -BootDevice VHD -VHDPath $VhdxPath -Path $virtualMachines -Generation 2 -Switch $VMSwitchName
Set-VM -VMName $VMname -ProcessorCount $CPUCount
Set-VMMemory -VMName $VMname -StartupBytes 8GB -DynamicMemoryEnabled $false
Set-VMSecurity -VMName $VMname -VirtualizationBasedSecurityOptOut $false
Set-VMKeyProtector -VMName $VMname -NewLocalKeyProtector
Enable-VMTPM -VMName $VMname
Enable-VMIntegrationService -VMName $VMname -Name "Guest Service Interface"
Set-VM -VMName $VMname -AutomaticCheckpointsEnabled $false | Out-Host

# Get serial number and rename VM
$serial = Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber
log "Serial number: $serial"

# trim serial
$subSerial = $serial.Substring(0, 4)
log "Trimmed serial number: $subSerial"


$newName = $name + "-" + $date + "-" + $version + "-" + $subSerial
log "New VM name: $newName"

try
{
    Rename-VM -Name $VMname -NewName $newName
    log "VM renamed to $newName"
}
catch
{
    log "Failed to rename VM to $newName"
    log "Error: $_"
    exit 1
}

