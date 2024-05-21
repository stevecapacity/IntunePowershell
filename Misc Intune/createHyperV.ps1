# Parameters for VMNAME, WINDOWS VERSION, and CPU COUNT
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$VMName,
    [Parameter(Mandatory=$True,Position=2)]
    [string]$version,
    [Parameter(Mandatory=$True,Position=3)]
    [string]$CPUCount
)

# Copy disk from TEMPLATES FOLDER and place in Hyper-V directory with VM name
Copy-Item -Path "D:\Templates\GM-$($version).vhdx" -Destination "D:\Hyper-V\Virtual hard disks\$($VMName).vhdx" -Force | Out-Null

# Set some VM definitions
$VMSwitchName = "Default Switch"
$VhdxPath = "D:\Hyper-V\Virtual hard disks\$($VMName).vhdx"
$VMPath = "D:\Hyper-V\Virtual machines"

# VM settings and create the VM
New-VM -Name $VMName -BootDevice VHD -VHDPath $VhdxPath -Path $VMPath -Generation 2 -Switch $VMSwitchName
Set-VM -VMName $VMName -ProcessorCount $CPUCount
Set-VMMemory -VMName $VMName -StartupBytes 8GB -DynamicMemoryEnabled $false
Set-VMSecurity -VMName $VMName -VirtualizationBasedSecurityOptOut $false
Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector
Enable-VMTPM -VMName $VMName
Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface"
Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false
