# Set parameters
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$name,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$version,

    [Parameter(Mandatory=$True,Position=3)]
    [string]$CPUcount,

    [Parameter(Mandatory=$False,Position=4)]
    [switch]$Autopilot=$False
)

# log function
function log()
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$message
    )
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    Write-Output "$date - $message"
}

# set drive volume and VM paths
$volume = "" # set the volume drive letter, for example "D:"
log "Hyper-V volume is $($volume)"

$templates = "$($volume)\Templates"
$virtualMachines = "$($volume)\Hyper-V\Virtual machines"
$virtualHardDisks = "$($volume)\Hyper-V\Virtual hard disks"

log "Checking for $virtualMachines..."
if(!(Test-Path $virtualMachines))
{
    log "$virtualMachines not found; creating directory..."
    try
    {
        mkdir $virtualMachines
        log "Directory $virtualMachines created"
    }
    catch
    {
        log "Failed to create $($virtualMachines) - Error: $_"
        Exit 1
    }
}
else
{
    log "Directory $virtualMachiens already exists."
}

log "Checking for $virtualHardDisks..."
if(!(Test-Path $virtualHardDisks))
{
    log "$virtualHardDisks not found; creating directory..."
    try 
    {
        mkdir $virtualHardDisks
        log "Directory $virtualHardDisks created"
    }
    catch 
    {
        log "Failed to create $($virtualHardDisks) - Error: $_"
        Exit 1
    }
}
else
{
    log "Directory $virtualHardDisks already exists."
}

# build the temp VM name
log "Generating temporary VM name..."
$number = Get-Random -Minimum 1000 -Maximum 10000
$numberString = $number.ToString()
$date = Get-Date -Format "MM-dd"
$VMName = $name + "-" + $date + "-" + $numberString
log "Temporarily setting VM name to $VMName"

# copy the GM disk
log "Copying the $version disk from $templates..."
try
{
    Copy-Item -Path "$($tempaltes)\GM-$($version).vhdx" -Destination "$($virtualHardDisks)\$($VMName).vhdx" -Force | Out-Null
    log "Disk coppied to $virtualHardDisks"
}
catch
{
    log "Failed to copy disk to $($virtualHardDisks) - Error: $_"
    Exit 1
}

# Virtual switch name
$VMSwitchName = "" # set the virtual switch name, for example "Default Switch"
log "Using virtual switch $($VMSwitchName)"

# build the VM
$vhdxPath = "$($virtualHardDisks)\$($VMName).vhdx"
log "Setting VHDX path to $($vhdxPath)"

New-VM -Name $VMName -BootDevice VHD -VHDPath $vhdxPath -Path $virtualMachines -Generation 2 -SwitchName $VMSwitchName
Set-VM -VMName $VMName -ProcessorCount $CPUcount
Set-VMMemory -VMName $VMName -StartupBytes 8GB -DynamicMemoryEnabled $false
Set-VMSecurity -VMName $VMName -VirtualizationBasedSecurityOptOut $False
Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector
Enable-VMTPM -VMName $VMName
Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface"
Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false | Out-Host

$serial = Get-WmiObject -ComputerName localhost -Namespace root\virtualization\v2 -class Msvm_VirtualSystemSettingData | Where-Object {$_.elementName -eq $VMName} | Select-Object -ExpandProperty BIOSSerialNumber
log "Serial number for $VMName is $($serial)"

# set the new VM name
log "Renaming VM..."
$subSerial = $serial.Substring(0,4)
log "Trimmed serial number to $subSerial"

$newVMName = $name + "-" + $date + "-" + $subSerial
log "New VM Name will be $newName"

try 
{
    Renamve-VM -Name $VMName -NewName $newVMName
    log "VM renamed to $newVMName"    
}
catch 
{
    log "Failed to rename VM to $($newName) - Error: $_"
    Exit 0
}


# (optional) Autopilot V2 info
if($Autopilot -eq $true)
{
    log "Autopilot switch is enabled.  Collecting hardware info for APV2 upload..."
    $exportPath = "C:\Autopilot"
    log "Checking for $($exportPath)..."
    if(!(Test-Path $exportPath))
    {
        log "$($exportPath) does not exist.  Creating..."
        mkdir $exportPath
        log "$($exportPath) directory created."
    }
    else
    {
        log "$($exportPath) directory already exists."
    }
    $data = "Microsoft Corporation,Virtual Machine,$($serial)"
    log "Autopilot V2 data is $($data)"
    log "Exporting to CSV..."
    Set-Content -Path "$($exportPath)\$($newVMName).csv" -Value $data
    log "Exported APV2 data to $($exportPath)\$($newVMName).csv"
}

