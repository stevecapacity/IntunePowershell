<# PRIMARY MIGRATION SCRIPT FOR INTUNE TENANT TO TENANT MIGRATION #>
<# WARNING: THIS MUST BE RUN AS SYSTEM CONTEXT #>
<#APP REG PERMISSIONS NEEDED:
Device.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementManagedDevices.PrivilegedOperations.All
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
#>

$ErrorActionPreference = 'SilentlyContinue'

<# =================================================================================================#>
#### STEP 1: LOCAL FILES AND LOGGING ####
<# =================================================================================================#>

#Copy necessary files from intunewin package to local PC
$resourcePath = "C:\ProgramData\IntuneMigration"

if (!(Test-Path $resourcePath)) {
	mkdir $resourcePath
}

$packageFiles = @(
	"migrate.ppkg",
	"AutopilotRegistration.xml",
	"AutopilotRegistration.ps1",
	"MigrateBitlockerKey.xml",
	"MigrateBitlockerKey.ps1",
	"SetPrimaryUser.xml",
	"SetPrimaryUser.ps1",
	"GroupTag.ps1",
	"GroupTag.xml",
	"MiddleBoot.ps1",
	"MiddleBoot.xml",
	"RestoreProfile.ps1",
	"RestoreProfile.xml"
)

foreach ($file in $packageFiles) {
	Copy-Item -Path "$($PSScriptRoot)\$($file)" -Destination "$($resourcePath)" -Force -Verbose
}

#Set detection flag for Intune install
Set-Content -Path "$($resourcePath)\Installed.txt" -Value "Package Installed"

#Start logging of script
Start-Transcript -Path "$($resourcePath)\migration.log" -Verbose

# Verify context is 
Write-Host "Running user..."
whoami
Write-Host ""


<# =================================================================================================#>
#### STEP 2: AUTHENTICATE TO MS GRAPH ####
<# =================================================================================================#>

#SOURCE TENANT Application Registration Auth 
Write-Host "Authenticating to MS Graph..."
$clientId = "<CLIENT ID>"
$clientSecret = "<CLIENT SECRET>"
$tenant = "TenantA.com"

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")

$body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)

$response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body

#Get Token form OAuth.
$token = -join ("Bearer ", $response.access_token)

#Reinstantiate headers.
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)
$headers.Add("Content-Type", "application/json")
Write-Host "MS Graph Authenticated"

<# =================================================================================================#>
#### STEP 3: GET CURRENT STATE INFO ####
<# =================================================================================================#>
#Gather Autopilot and Intune Object details

Write-Host "Gathering device info..."
$serialNumber = Get-WmiObject -Class Win32_Bios | Select-Object -ExpandProperty serialnumber
Write-Host "Serial number is $($serialNumber)"

$autopilotObject = Invoke-RestMethod -Method Get -uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($serialNumber)')" -headers $headers
$intuneObject = Invoke-RestMethod -Method Get -uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=contains(serialNumber,'$($serialNumber)')" -headers $headers

$autopilotID = $autopilotObject.value.id
Write-Host "Autopilot ID is $($autopilotID)"
$intuneID = $intuneObject.value.id
Write-Host "Intune ID is $($intuneID)"
$groupTag = $autopilotObject.value.groupTag
Write-Host "Current Autopilot GroupTag is $($groupTag)."

<#===============================================================================================#>
# Get active username
$activeUsername = (Get-WMIObject Win32_ComputerSystem | Select-Object username).username
$user = $activeUsername -replace '.*\\'
Write-Host "Current active user is $($user)"

Start-Sleep -Seconds 3

<#===============================================================================================#>
#Save device information to local XML
$xmlString = "<Config>
<GroupTag>$groupTag</GroupTag>
<User>$user</User>
</Config>"

New-Item -ItemType File -Path "$($resourcePath)" -Name "MEM_Settings.xml" -Force
Add-Content $xmlPath $xmlString | Set-Content $xmlPath -Force
Write-Host "Setting local content to $($xmlPath)"

<# =================================================================================================#>
#### STEP 4: SET REQUIRED POLICY ####
<# =================================================================================================#>
# Ensure Microsoft Account creation policy is enabled

$regPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts"
$regName = "AllowMicrosoftAccountConnection"
$value = 1

$currentRegValue = Get-ItemPropertyValue -Path $regPath -name $regName -ErrorAction SilentlyContinue

if ($currentRegValue -eq $value) {
	Write-Host "Registry value for AllowMicrosoftAccountConnection is correctly set to $value."
}
else {
	Write-Host "Setting MDM registry value for AllowMicrosoftAccountConnection..."
	reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts" /v "AllowMicrosoftAccountConnection" /t REG_DWORD /d 1 /f | Out-Host
}

<#===============================================================================================#>
# Only show OTHER USER option after reboot
Write-Host "Turning off Last Signed-In User Display...."
try {
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name dontdisplaylastusername -Value 1 -Type DWORD -Force
	Write-Host "Enabled Interactive Logon policy"
} 
catch {
	Write-Host "Failed to enable policy"
}

<# =================================================================================================#>
#### STEP 5: USER DATA MIGRATION ####
<# =================================================================================================#>

# Check local user data size and available disk space
# Paths can be added or removed from this array as needed without affecting the migration.  Note that more paths will mean more files will mean larger data sizes...
$locations = @(
	"AppData\Local"
	"AppData\Roaming"
	"Documents"
	"Desktop"
	"Pictures"
)

$totalProfileSize = 0

foreach($location in $locations)
{
	$size = (Get-ChildItem "C:\Users\$($user)\$($location)" -Recurse | Measure-Object Length -Sum).sum
	$totalProfileSize += $size
	$sizeGB = "{0:N2} Gb" -f ($totalProfileSize/ 1Gb)
	Write-Host "C:\Users\$($user)\$($location) size is $($sizeGB)"
}

$totalProfileSizeGB = "{0:N2} GB" -f ($totalProfileSize/ 1Gb)
Write-Host "The size of $($user) user data is $($totalProfileSizeGB)."

$diskSize = Get-Volume -DriveLetter C | Select-Object SizeRemaining -ExpandProperty SizeRemaining
$diskSizeGB = "{0:N2} GB" -f ($diskSize/ 1Gb)
Write-Host "There is $($diskSizeGB) of free space available on the PC."

$neededSpace = $totalProfileSize * 3
$neededSpaceGB = "{0:N2} GB" -f ($neededSpace/ 1Gb)
Write-Host "$($neededSpaceGB) is required to transfer local user data."

<#===============================================================================================#>
# If disk space available, tranfer data.

if($diskSize -gt $neededSpace)
{
    Write-Host "$($diskSizeGB) of free space is sufficient to transfer $($totalProfileSizeGB) of local user data.  Begin transfer..." -ForegroundColor Green
	
	foreach($location in $locations)
	{
		$userPath = "C:\Users\$($user)\$($location)"
		$publicPath = "C:\Users\Public\Temp\$($location)"
		if(!(Test-Path))
		{
			mkdir $publicPath
		}
		Write-Host "Initiating backup of $($location)"
		robocopy $userPath $publicPath /E /ZB /R:0 /W:0 /V /XJ /FFT
	}
}
else
{
    Write-Host "$($diskSizeGB) is not sufficient to transfer $($totalProfileSizeGB) of local user data.  Consider backingup $($user) data to external storage." -ForegroundColor Red
}



<# =================================================================================================#>
#### STEP 6: REMOVE PREVIOUS ENROLLMENT ARTIFICATS ####
<# =================================================================================================#>
#Remove previous MDM enrollment settings from registry

Get-ChildItem 'Cert:\LocalMachine\My' | Where-Object { $_.Issuer -match "Microsoft Intune MDM Device CA" } | Remove-Item -Force

$EnrollmentsPath = "HKLM:\Software\Microsoft\Enrollments\"
$ERPath = "HKLM:\Software\Microsoft\Enrollments\"
$Enrollments = Get-ChildItem -Path $EnrollmentsPath
foreach ($enrollment in $Enrollments) {
	$object = Get-ItemProperty Registry::$enrollment
	$discovery = $object."DiscoveryServiceFullURL"
	if ($discovery -eq "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc") {
		$enrollPath = $ERPath + $object.PSChildName
		Remove-Item -Path $enrollPath -Recurse
	}
}

<#===============================================================================================#>
#Remove previous MDM enrollment tasks in task scheduler
$enrollID = $enrollPath.Split('\')[-1]

$taskPath = "\Microsoft\Windows\EnterpriseMgmt\$($enrollID)\"

$tasks = Get-ScheduledTask -TaskPath $taskPath

if ($tasks.Count -gt 0) {
	Write-Host "Deleting tasks in folder: $taskPath"
	foreach ($task in $tasks) {
		$taskName = $task.TaskName
		Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
		Write-Host "Deleted task: $taskName"
	}
}
else {
	Write-Host "No tasks found in folder: $taskPath"
}

Write-Host "Removed previous Intune enrollment"

<# =================================================================================================#>
#### STEP 7: LEAVE AZURE AD AND INTUNE ####
<# =================================================================================================#>

#Remove device from Current Azure AD and Intune environment

Write-Host "Leaving the $($tenant) Azure AD and Intune environment"
Start-Process "C:\Windows\sysnative\dsregcmd.exe" -ArgumentList "/leave"

Start-Sleep -Seconds 5

<# =================================================================================================#>
#### STEP 8: SET POST-MIGRATION TASKS ####
<# =================================================================================================#>

#Create post-migration tasks

foreach($file in $packageFiles)
{
    if($file -match '.xml')
    {
        $name = $file.Split('.')[0]
        schtasks /create /TN $($name) /xml "$($resourcePath)\$($file)" /f
		Write-Host "Created $($name) task"
    }
}

<# =================================================================================================#>
#### STEP 9: JOIN TENANT B ####
<# =================================================================================================#>

#Run ppkg to enroll into new tenant
Write-Host "Installing provisioning package for new Azure AD tenant"
Install-ProvisioningPackage -PackagePath "$($resourcePath)\migrate.ppkg" -QuietInstall -Force

<# =================================================================================================#>
#### STEP 10: DELETE OBJECTS FROM TENANT A AND REBOOT ####
<# =================================================================================================#>

#Delete Intune and Autopilot objects from old tenant
if ($intuneID -eq $null) {
	Write-Host "Intune ID is null.  Skipping Intune object deletion..."
}
else {
	Write-Host "Attempting to Delete the Intune object..."
	try {
		Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($intuneID)" -Headers $headers
		Start-Sleep -Seconds 2
		Write-Host "Intune object deleted."
	}
 catch {
		Write-Host "Intune object deletion failed.  Trying again..."
		Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
		Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
	}

}

if ($autopilotID -eq $null) {
	Write-Host "Autopilot ID is null.  Skipping Autopilot object deletion..."
}
else {
	Write-Host "Attempting to Delete the Autopilot object..."
	try {
		Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($autopilotID)" -Headers $headers
		Start-Sleep -Seconds2
		Write-Host "Autopilot object deleted."
	}
 catch {
		Write-Host "Autopilot object deletion failed.  Trying again..."
		Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
		Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
	}
}

<#===============================================================================================#>
# Reboot
Shutdown -r -t 30

Stop-Transcript
