# Parameters for VMNAME, WINDOWS VERSION, and CPU COUNT
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$Name,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$version,

    [Parameter(Mandatory=$True,Position=3)]
    [string]$CPUCount,
    
    [Parameter(Mandatory=$False,Position=4)]
    [switch]$Autopilot = $False
)

$number = Get-Random -Minimum 1000 -Maximum 10000
$numberString = $number.ToString()
$VMName = $Name + "-" + $version + "-" + $numberString

# Copy disk from TEMPLATES FOLDER and place in Hyper-V directory with VM name
Copy-Item -Path "D:\Templates\GM-$($version).vhdx" -Destination "C:\Hyper-V\Virtual hard disks\$($VMName).vhdx" -Force | Out-Null

# Set some VM definitions
$VMSwitchName = "Default Switch"
$VhdxPath = "C:\Hyper-V\Virtual hard disks\$($VMName).vhdx"
$VMPath = "C:\Hyper-V\Virtual machines"

# VM settings and create the VM
New-VM -Name $VMName -BootDevice VHD -VHDPath $VhdxPath -Path $VMPath -Generation 2 -Switch $VMSwitchName
Set-VM -VMName $VMName -ProcessorCount $CPUCount
Set-VMMemory -VMName $VMName -StartupBytes 8GB -DynamicMemoryEnabled $false
Set-VMSecurity -VMName $VMName -VirtualizationBasedSecurityOptOut $false
Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector
Enable-VMTPM -VMName $VMName
Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface"
Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false | Out-Host

if($Autopilot -eq $True)
{
    # make a path to export the csv to
    $exportPath = "C:\Autopilot"
    if(!(Test-Path $exportPath))
    {
        mkdir $exportPath
    }
    # get the hardware info: manufacturer, model, serial
    $serial = Get-WmiObject -ComputerName localhost -Namespace root\virtualization\v2 -class Msvm_VirtualSystemSettingData | Where-Object {$_.elementName -eq $VMName} | Select-Object -ExpandProperty BIOSSerialNumber
    $data = "Microsoft Corporation,Virtual Machine,$($serial)"
    # add to CSV file in path
    Set-Content -Path "$($exportPath)\$($VMName).csv" -Value $data
}