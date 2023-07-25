<# PRIMARY MIGRATION SCRIPT FOR INTUNE TENANT TO TENANT MIGRATION #>
<# WARNING: THIS MUST BE RUN AS SYSTEM CONTEXT #>


$ErrorActionPreference = 'SilentlyContinue'

function Get-GraphPagedResult {
	param ([parameter(Mandatory = $true)]$Headers, [parameter(Mandatory = $true)]$Uri, [Parameter(Mandatory = $false)][switch]$Verb)

	$amalgam = @()
	$pages = 0

	do {
		$results = Invoke-RestMethod $Uri -Method "GET" -Headers $Headers

		if ($results.value) { $amalgam += $results.value }
		else { $amalgam += $results }

		$pages += 1

		if ($Verb) { Write-Host "Completed searching MSGraph page $pages ..." }	

		$Uri = $results.'@odata.nextlink'	
	} until (!($Uri))
	
	$amalgam
}

function Get-TimeStamp {
    
	return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
}

<#PERMISSIONS NEEDED:
Device.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementManagedDevices.PrivilegedOperations.All
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
#>

$resourcePath = "C:\Resources"

if (!(Test-Path $resourcePath)) {
	mkdir $resourcePath
}


#Start logging of script
Start-Transcript -Path "C:\Resources\migration.log" -Verbose


Write-Host "Running user..."
whoami
Write-Host ""

#<-------------------------------------------------------------------------------------------------------------------------------------------------->
#<-------------------------------------------------------------------------------------------------------------------------------------------------->

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

#<-------------------------------------------------------------------------------------------------------------------------------------------------->
#<-------------------------------------------------------------------------------------------------------------------------------------------------->

#Gather Autopilot and Intune Object details

Write-Host "Gathering device info..."
$serialNumber = Get-WmiObject -Class Win32_Bios | Select-Object -ExpandProperty serialnumber
Write-Host "Serial number is $($serialNumber)"

$autopilotObject = Invoke-RestMethod -Method Get -uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($serialNumber)')" -headers $headers
$intuneObject = Invoke-RestMethod -Method Get -uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers

$autopilotID = $autopilotObject.value.id
Write-Host "Autopilot ID is $($autopilotID)"
$intuneID = $intuneObject.value.id
Write-Host "Intune ID is $($intuneID)"
$groupTag = $autopilotObject.value.groupTag
Write-Host "Current Autopilot GroupTag is $($groupTag)."


Start-Sleep -Seconds 3

<#===============================================================================================#>

#Copy necessary files from intunewin package
$files = @(
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
foreach ($file in $files) {
	Copy-Item -Path "$($PSScriptRoot)\$($file)" -Destination "$($resourcePath)" -Force -Verbose
}


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

<#===============================================================================================
COPY LOCAL PROFILE TO PUBLIC TEMP
===============================================================================================#>
$activeUsername = (Get-WMIObject Win32_ComputerSystem | Select-Object username).username
$user = $activeUsername -replace '.*\\'

$publicTempLocalPath = "C:\Users\Public\Temp\Local"
$publicTempRoamingPath = "C:\Users\Public\Temp\Roaming"
$publicTempDesktopPath = "C:\Users\Public\Temp\Desktop"
$publicTempDocumentsPath = "C:\Users\Public\Temp\Documents"
$publicTempDownloadsPath = "C:\Users\Public\Temp\Downloads"

if (!(Test-Path $publicTempLocalPath)) {
	mkdir $publicTempLocalPath
}

if (!(Test-Path $publicTempRoamingPath)) {
	mkdir $publicTempRoamingPath
}

if (!(Test-Path $publicTempDesktopPath)) {
	mkdir $publicTempDesktopPath
}

if (!(Test-Path $publicTempDocumentsPath)) {
	mkdir $publicTempDocumentsPath
}

if (!(Test-Path $publicTempDownloadsPath)) {
	mkdir $publicTempDownloadsPath
}

Write-Host "Starting file copy"

$localAppDataPath = "C:\Users\$($user)\AppData\Local"
$roamingAppDataPath = "C:\Users\$($user)\AppData\Roaming"
$desktopPath = "C:\Users\$($user)\Desktop"
$documentsPath = "C:\Users\$($user)\Documents"
$downloadsPath = "C:\Users\$($user)\Documents"

Write-Host "$(Get-TimeStamp) - Initiating Backup of Local App Data"
robocopy $localAppDataPath $publicTempLocalPath /E /ZB /R:0 /W:0 /V /XJ /FFT
Write-Host "$(Get-TimeStamp) - Initiating Backup of Roaming App Data"
robocopy $roamingAppDataPath $publicTempRoamingPath /E /ZB /R:0 /W:0 /V /XJ /FFT
Write-Host "$(Get-TimeStamp) - Initiating Backup of Desktop"
robocopy $desktopPath $publicTempDesktopPath /E /ZB /R:0 /W:0 /V /XJ /FFT
Write-Host "$(Get-TimeStamp) - Initiating Backup of Documents"
robocopy $documentsPath $publicTempDocumentsPath /E /ZB /R:0 /W:0 /V /XJ /FFT
Write-Host "$(Get-TimeStamp) - Initiating Backup of Downloads"
robocopy $downloadsPath $publicTempDownloadsPath /E /ZB /R:0 /W:0 /V /XJ /FFT


$xmlString = "<Config>
<GroupTag>$groupTag</GroupTag>
<User>$user</User>
</Config>"

#Save device information to local XML
$xmlPath = "C:\Resources\MEM_Settings.xml"


New-Item -ItemType File -Path "C:\Resources" -Name "MEM_Settings.xml" -Force
Add-Content $xmlPath $xmlString | Set-Content $xmlPath -Force
Write-Host "Setting local content..."

<#===============================================================================================#>


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


Set-Content -Path "$($resourcePath)\flag.txt" -Value "Installed"


try
{
	Start-Process "C:\Windows\sysnative\dsregcmd.exe" -ArgumentList "/leave"
}
catch
{
	Start-Process "C:\Windows\System32\dsregcmd.exe" -ArgumentList "/leave"
}

Write-Host "Commands have run to attempt leave of Azure AD"
Start-Sleep -Seconds 5


#Create tasks to update primary user, autopilot record, and bitlocker key in new tenant (post-migration)

schtasks /create /TN "Set Primary Users" /xml "C:\Resources\SetPrimaryUser.xml" /f
schtasks /create /TN "GroupTag" /xml "C:\Resources\GroupTag.xml" /f
Write-Host "Set Primary User task is scheduled"

schtasks /create /TN "Autopilot Registration" /xml "C:\Resources\AutopilotRegistration.xml" /f
Write-Host "Autopilot registration to Tenerity task scheduled"

schtasks /create /TN "Migrate Bitlocker Key" /xml "C:\Resources\MigrateBitlockerKey.xml" /f
Write-Host "Bitlocker key escrow task scheduled"
schtasks /create /TN "Run and Reboot" /xml "C:\Resources\MiddleBoot.xml" /f
Write-Host "Middle boot task scheduled"

schtasks /create /TN "Restore Profile" /xml "C:\Resources\RestoreProfile.xml" /f
Write-Host "Profile restore task scheduled"

#Run ppkg to enroll into new tenant

Install-ProvisioningPackage -PackagePath "C:\Resources\migrate.ppkg" -QuietInstall -Force




#Delete Intune and Autopilot objects from old tenant
if ($intuneID -eq $null) {
	Write-Host "Intune ID is null.  Skipping Intune object deletion..."
}
else {
	Write-Host "Attempting to Delete the Intune object..."
	try {
		Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($intuneID)" -Headers $headers
		Start-Sleep -Seconds 5
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
		Start-Sleep -Seconds 5
		Write-Host "Autopilot object deleted."
	}
 catch {
		Write-Host "Autopilot object deletion failed.  Trying again..."
		Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
		Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
	}
}



# Only show OTHER USER option after reboot
Write-Host "Turning off Last Signed-In User Display...."
try {
	Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name dontdisplaylastusername -Value 1 -Type DWORD -Force
	Write-Host "Enabled Interactive Logon GPO"
} 
catch {
	Write-Host "Failed to enable GPO"
}

Shutdown -r -t 30

Stop-Transcript