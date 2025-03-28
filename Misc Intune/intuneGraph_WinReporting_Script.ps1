

<#NOTES:
This script has been compiled over time based on various reporting needs for Intune-managed devices - 
it has a lot of repeated stuff due to development for different needs over time. Please be nice :)

Once the CSV is exported, you can optionally import the file into an excel template for filtering and conditional formatting.
Like any public script off the interwebs, there are no guarantees expressed or implied for all functions to work properly.
#>

#Target "All" or a specific security group for reporting
Write-Host ""
$targetDeviceGroupName = Read-Host 'Enter the name of the desired group you would like to target for reporting. You may type "All" to target all devices'
Write-Host ""

#Target "All" or a specific Windows Feature Update profile
$TARGET_UPDATE_PROFILE = Read-Host "Please enter the display name of your Feature Update profile. You may enter 'All' to get device statuses from all profiles"
Write-Host "`n"

#Function to properly search all graph results
function Get-GraphPagedResult
{
    param ([parameter(Mandatory = $true)]$Headers,[parameter(Mandatory = $true)]$Uri,[Parameter(Mandatory=$false)][switch]$Verb)
    $amalgam = @()
    $pages = 0
    do
    {
        $results = Invoke-RestMethod $Uri -Method "GET" -Headers $Headers
        if ($results.value)
            {$amalgam += $results.value}
        else
            {$amalgam += $results}
        $pages += 1

        if($Verb)
        {Write-Host "Completed page $pages for url $Uri"}

        $Uri = $results.'@odata.nextlink'

    } until (!($Uri))

    $amalgam
}

#############################################################
###############  App registration / token  ##################

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Web

#APPLICATION-BASED PERMISSIONS NEEDED:
#Device.Read.All
#DeviceManagementConfiguration.ReadWrite.All (ReadWrite needed for export job for Feature Update Reports)
#DeviceManagementManagedDevices.Read.All
#DeviceManagementServiceConfig.Read.All
#Directory.Read.All
#Group.Read.All
#GroupMember.Read.All 

function Connect_To_Graph {
    #App registration
    $tenant = "primary-or-federated-domain"
    $clientId = "APPLICATION-ID"
    $clientSecret = "SECRET-VALUE"
    $clientSecret = [System.Web.HttpUtility]::UrlEncode($clientSecret)

    #Header and body request variables
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
    $body += -join("&client_id=" , $clientId, "&client_secret=", $clientSecret)
    $response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $header -Body $body
    $token = -join("Bearer ", $response.access_token)
    #Reinstantiate headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")

    $headers
    Start-Sleep -Seconds 3
}

$headers = Connect_To_Graph

#NOTE: If you prefer to use delegated permissions instead, replace lines 61-77 with the following instead:
<#
$tenant = "primary-or-federated-domain"
$clientId = "APPLICATION-ID"

$AccessToken = Get-MsalToken -TenantId $tenant -ClientId $clientId -ForceRefresh
$authHeader = $AccessToken.CreateAuthorizationHeader()

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

$headers.Add("Content-Type", "application/json")
$headers.Add("Authorization", "$($authHeader)")
$headers.Add("Accept", "application/json")
#>

#############################################################
#############################################################

# Start gathering all Intune Windows devices records

$intuneDevices = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'" -Headers $headers -Verb

# Get targetted group information

if($targetDeviceGroupName -ne "All")
{
    Write-Host "Querying Azure group by display name..."
    $groupPayload = Invoke-RestMethod "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$($targetDeviceGroupName)'" -Method "GET" -Headers $headers
    if ($groupPayload.value.Length -eq 0)
    {
        Write-Error "Group with name $targetDeviceGroupName does not exist. Closing Script..."
        exit -1
    }

    $theGroup = $groupPayload.value[0]
    $groupDeviceIds = @()
    Write-Host "Querying members of retrieved Azure group..."
    $groupDevices = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/groups/$($theGroup.id)/members" -Headers $headers -Verb

    foreach($dev in $groupDevices)
    {
        $groupDeviceIds += $dev.deviceId
    }
}

# Get Update Ring policies and details

$updateRingsStatus = @()

$updateRings = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=(isof('microsoft.graph.windowsUpdateForBusinessConfiguration'))" -Headers $headers -Verb
$ringCount = 1

foreach($ring in $updateRings)
{
    Write-Host "Getting device details from Ring $ringCount ($($ring.displayName))..."
    $ringDeviceStatusAll = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($ring.id)/deviceStatuses" -Headers $headers -Verb
    #Filter to System account, omit UPN entries
    $ringDeviceStatus = $ringDeviceStatusAll | Where-Object {$_.UserPrincipalName -eq "System account"}
    
    Write-Host "Updating status array for ring $ringCount..."

    foreach($device in $ringDeviceStatus)
    {
        $updateRingsStatus += New-Object -TypeName PSObject -Property @{
            "Ring" = $($ring.displayName); 
            "Device" = $($device.deviceDisplayName); 
            "Status" = $($device.status);
        }
    }
    $ringCount += 1
}

Start-Sleep -Seconds 5


# Manual re-authentication to app reg (NOTE: This may not be needed depending on number of profiles and device statuses exported thus far; this was necessary for tenants with 25k+ devices)
$headers = Connect_To_Graph


# Get Device Health Attestation Report details (NOTE: Tried previously calling this per device, but graph always returned unknown. This is the call that is made when navigating to Devices -> Monitor -> Windows health attestation report)
Write-Host "Getting Device Health Attestation Report..."
$deviceHealthAttestationReport = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=isof('microsoft.graph.windowsManagedDevice')&`$select=deviceHealthAttestationState,deviceName,operatingSystem,id" -Headers $headers -Verb

# Get Encryption Report details (NOTE: Filtering by device name does not appear to work, therefore the full report is gathered in advance)
Write-Host "Getting Device Encryption Report..."
$encryptionReport = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDeviceEncryptionStates?`$select=advancedBitLockerStates,deviceName,encryptionReadinessState" -Headers $headers -Verb

<# This call seems to often timeout when paired with the previous calls. Re-running might work, but repeated authentication on line 160 instead.
if(!($encryptionReport))
{
    Write-Host "Gateway timeout likely occured - re-running call..."
    $encryptionReport = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDeviceEncryptionStates?`$select=advancedBitLockerStates,deviceName,encryptionReadinessState" -Headers $headers -Verb
}
#>

##############################################################
############  Get the Feature Update profiles  ###############

# If you are deploying a Feature Update policy, this section will pull a report from Intune's Reports -> Windows Update -> Feature Update report
# NOTE: If you specify 'All' Feature Update profiles, it will take a bit to perform the export job for each profile


$profiles = Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles" -Method "GET" -Headers $headers

if($TARGET_UPDATE_PROFILE -eq 'All')
{
    $featureUpdateReport = @()
    Write-Host "Please wait - this make take a bit to export all $($profiles.value.count) Feature Update profiles..."

    foreach($profile in $profiles.value)
    {
        $profileName = $profile.displayName
        $profileId = $profile.id

        Write-Output "Now assessing profile $profileName"
        $payload = @{
            reportName = "FeatureUpdateDeviceState";
            filter = "(PolicyId eq '$($profileId)')";
            localizationType = "LocalizedValuesAsAdditionalColumn";
            select = @(
                "PolicyId",
                "PolicyName",
                "FeatureUpdateVersion",
                "DeviceId",
                "AADDeviceId",
                "PartnerPolicyId",
                "EventDateTimeUTC",
                "LastSuccessfulDeviceUpdateStatus",
                "LastSuccessfulDeviceUpdateSubstatus",
                "LastSuccessfulDeviceUpdateStatusEventDateTimeUTC",
                "CurrentDeviceUpdateStatus",
                "CurrentDeviceUpdateSubstatus",
                "CurrentDeviceUpdateStatusEventDateTimeUTC",
                "LatestAlertMessage",
                "LatestAlertMessageDescription",
                "LatestAlertRecommendedAction",
                "LatestAlertExtendedRecommendedAction",
                "UpdateCategory",
                "WindowsUpdateVersion",
                "LastWUScanTimeUTC",
                "Build",
                "DeviceName",
                "OwnerType",
                "UPN",
                "AggregateState"        
            );
        }

        $payload = $payload | ConvertTo-Json

        #Generate job to export report
        $jobGenResult = Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs" -Method "POST" -Headers $headers -Body $payload
        Write-Output $jobGenResult

        #Keep polling til the blob link appears
        Write-Output "Now starting extraction of report for profile $profileName"
        $reportUrl = ""

        while($true)
        {
            Start-Sleep -Seconds 10
            $report = Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$($jobGenResult.id)')" -Method "GET" -Headers $headers
            if($null -ne $report.url)
            {
                Write-Output "Report extraction successful. Url loaded. Now pulling report..."
                $reportUrl = $report.url
                break
            }
            Write-Output "Report unavailable. Trying again in 10 seconds..."
        }

        #In case there are special characters, which screws up downloading and creating directory/zip
        $trimmedProfileName = $profileName -replace '[^A-Za-z0-9\s]',''

        if(Test-Path "$psscriptroot\data\$trimmedProfileName")
        {
            Remove-Item "$psscriptroot\data\$trimmedProfileName" -Force -Recurse
        }

        New-Item -Path "$psscriptroot\data" -Name "$trimmedProfileName" -ItemType "directory"
        Invoke-WebRequest -Uri $reportUrl -OutFile "$psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName.zip"
        Write-Output "Report downloaded for profile $profileName"

        Expand-Archive "$psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName.zip" -DestinationPath "$psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName"

        $theFileName = Get-ChildItem -Path "$psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName" | Select -ExpandProperty FullName | Select-Object -first 1
        $featureUpdateReport += Import-Csv -Path $theFileName
    }
}

else
{
    $theProfile = @()
    foreach($p in $profiles.value){
        if ($p.displayName -eq $($TARGET_UPDATE_PROFILE)){
            $theProfile = $p
            break
        }
    }

    $profileName = $theProfile.displayName
    Write-Output "Now assessing profile $profileName"

    $payload = @{
        reportName = "FeatureUpdateDeviceState";
        filter = "(PolicyId eq '$($theProfile.id)')";
        localizationType = "LocalizedValuesAsAdditionalColumn";
        select = @(
            "PolicyId",
            "PolicyName",
            "FeatureUpdateVersion",
            "DeviceId",
            "AADDeviceId",
            "PartnerPolicyId",
            "EventDateTimeUTC",
            "LastSuccessfulDeviceUpdateStatus",
            "LastSuccessfulDeviceUpdateSubstatus",
            "LastSuccessfulDeviceUpdateStatusEventDateTimeUTC",
            "CurrentDeviceUpdateStatus",
            "CurrentDeviceUpdateSubstatus",
            "CurrentDeviceUpdateStatusEventDateTimeUTC",
            "LatestAlertMessage",
            "LatestAlertMessageDescription",
            "LatestAlertRecommendedAction",
            "LatestAlertExtendedRecommendedAction",
            "UpdateCategory",
            "WindowsUpdateVersion",
            "LastWUScanTimeUTC",
            "Build",
            "DeviceName",
            "OwnerType",
            "UPN",
            "AggregateState"        
        );
    }

    $payload = $payload | ConvertTo-Json

    #Generate job to export report
    $jobGenResult = Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs" -Method "POST" -Headers $headers -Body $payload
    Write-Output $jobGenResult

    #Keep polling til the blob link appears
    Write-Output "Now starting extraction of report for profile $profileName"
    $reportUrl = ""

    while($true)
    {
            Start-Sleep -Seconds 10
            $report = Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$($jobGenResult.id)')" -Method "GET" -Headers $headers
            if($null -ne $report.url)
            {
                Write-Output "Report extraction successful. Url loaded. Now pulling report..."
                $reportUrl = $report.url
                break
            }
            Write-Output "Report unavailable. Trying again in 10 seconds..."
    }

    #In case there are special characters, which screws up downloading and creating directory/zip
    $trimmedProfileName = $profileName -replace '[^A-Za-z0-9\s]',''

    if(Test-Path "$psscriptroot\data\$trimmedProfileName")
    {
            Remove-Item "$psscriptroot\data\$trimmedProfileName" -Force -Recurse
    }

    New-Item -Path "$psscriptroot\data" -Name "$trimmedProfileName" -ItemType "directory"
    Invoke-WebRequest -Uri $reportUrl -OutFile "$psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName.zip"
    Write-Output "Report downloaded for profile $profileName"

    Expand-Archive "$psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName.zip" -DestinationPath "$psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName"

    $theFileName = Get-ChildItem -Path "$psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName" | Select -ExpandProperty FullName | Select-Object -first 1
    $featureUpdateReport = Import-Csv -Path $theFileName
}


# Manual re-authentication to app reg (NOTE: This may not be needed depending on number of profiles and device statuses exported thus far)
$headers = Connect_To_Graph


#############################################################
######                                                 ######
######              Begin Tracking Devices             ######
######                                                 ######
#############################################################

$outarray = @()
$deviceCount = 0

foreach($device in $intuneDevices)
{

    if($targetDeviceGroupName -ne "All" -and $groupDeviceIds -notcontains $device.azureActiveDirectoryDeviceId)
    {
        continue
    }
    $deviceCount += 1
    
#DEVICE VARIABLES FOR REPORTING (For reference: https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0&viewFallbackFrom=graph-rest-beta&tabs=http)
    $deviceId = $device.id
    $deviceAADid = $device.azureActiveDirectoryDeviceId
    $deviceName = $device.deviceName
    $deviceLastSync = $device.lastSyncDateTime
    $deviceSync = $deviceLastSync.split("T")[0]         #This will be in UTC
    #$deviceSync = [datetime]::Parse($deviceLastSync).ToString('MM-dd-yyyy')
    $deviceUPN = $device.userPrincipalName
    $deviceCompliance = $device.complianceState
    $deviceJoinType = $device.joinType
    $deviceAutopilotEnrolled = $device.autopilotEnrolled
    $deviceEnrollmentProfileName = $device.enrollmentProfileName

    #Additional call for hardware details...
    $deviceAdditionalInfo = Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($deviceId)?`$select=chassisType,ethernetMacAddress,hardwareInformation,physicalMemoryInBytes,processorArchitecture,roleScopeTagIds" -Method "GET" -Headers $headers
    $deviceHardwareInfo = $deviceAdditionalInfo.hardwareInformation
    [string]$deviceScopeTags = $deviceAdditionalInfo.roleScopeTagIds
    $deviceSerial = $device.serialNumber
    $deviceChassis = $deviceAdditionalInfo.chassisType
    $deviceManufacturer = $deviceHardwareInfo.manufacturer
    $deviceModel = $deviceHardwareInfo.model
    $deviceBiosVersion = $deviceHardwareInfo.systemManagementBIOSVersion
    $deviceOsVersion = $device.osVersion
    $deviceOsEdition = $deviceHardwareInfo.operatingSystemEdition
    $deviceArchitecture = $deviceAdditionalInfo.processorArchitecture
    $deviceTpmSpecVersion = $deviceHardwareInfo.tpmSpecificationVersion
    $deviceTpmManufacturer = $deviceHardwareInfo.tpmManufacturer
    $deviceTpmMfrVersion = $deviceHardwareInfo.tpmVersion
    $deviceIpAddress = $deviceHardwareInfo.ipAddressV4
    $deviceIpSubnet = $deviceHardwareInfo.subnetAddress
    [string]$deviceWiredIpAddress = $deviceHardwareInfo.wiredIPv4Addresses
    $deviceEthernetMacAddress = $deviceAdditionalInfo.ethernetMacAddress
    $deviceTotalStorage = $deviceHardwareInfo.totalStorageSpace
    $deviceFreeStorage = $deviceHardwareInfo.freeStorageSpace
    $deviceLicenseStatus = $deviceHardwareInfo.deviceLicensingStatus

    #additional call for Defender info...
    $deviceWinSecurity = Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($deviceId)/windowsProtectionState" -Method "GET" -Headers $headers
    $deviceMalwareProtection = $deviceWinSecurity.malwareProtectionEnabled
    $deviceWinSecurityState = $deviceWinSecurity.deviceStatuses
    $deviceRealTimeProtection = $deviceWinSecurity.realTimeProtectionEnabled
    $deviceNetworkInspectionEnabled = $deviceWinSecurity.networkInspectionSystemEnabled
    $deviceQuickScanOverdue = $deviceWinSecurity.quickScanOverdue
    $deviceFullScanOverdue = $deviceWinSecurity.fullScanOverdue
    $deviceSignatureUpdateRequired = $deviceWinSecurity.signatureUpdateOverdue
    $deviceRebootRequired = $deviceWinSecurity.rebootRequired
    $deviceFullScanRequired = $deviceWinSecurity.fullScanRequired
    $deviceSecurityEngineVersion = $deviceWinSecurity.engineVersion
    $deviceSecuritySignatureVersion = $deviceWinSecurity.signatureVersion
    $deviceSecurityAntiMalwareVersion = $deviceWinSecurity.antiMalwareVersion
    if($deviceWinSecurity.lastQuickScanDateTime){$deviceSecuritylastQuickScan = ($deviceWinSecurity.lastQuickScanDateTime).split("T")[0]} else {$deviceSecuritylastQuickScan = "unknown"}
    if($deviceWinSecurity.lastFullScanDateTime){$deviceSecuritylastFullScan = ($deviceWinSecurity.lastFullScanDateTime).split("T")[0]} else {$deviceSecuritylastFullScan = "unknown"}
    $deviceSecuritylastQuickScanSignatureVersion = $deviceWinSecurity.lastQuickScanSignatureVersion
    $deviceSecuritylastFullScanSignatureVersion = $deviceWinSecurity.lastFullScanSignatureVersion
    if($deviceWinSecurity.lastReportedDateTime){$deviceSecuritylastReported = ($deviceWinSecurity.lastReportedDateTime).split("T")[0]} else {$deviceSecuritylastReported = "unknown"}
    $deviceSecurityproductStatus = $deviceWinSecurity.productStatus
    $deviceSecurityisVirtualMachine = $deviceWinSecurity.isVirtualMachine
    $deviceSecuritytamperProtectionEnabled = $deviceWinSecurity.tamperProtectionEnabled

    #device health attestation info...
    $deviceHealthAttestation = $null
    foreach($report in $deviceHealthAttestationReport)
    {
        if($report.deviceName -eq $deviceName)
        {
            $deviceHealthAttestation = $report.deviceHealthAttestationState
            $deviceHealthAttestationStatus = $deviceHealthAttestation.deviceHealthAttestationStatus
            $deviceHealthAttestationSupportStatus = $deviceHealthAttestation.healthAttestationSupportStatus
            $deviceHealthAttestationKey = $deviceHealthAttestation.attestationIdentityKey
            $deviceBitLockerStatus = $deviceHealthAttestation.bitLockerStatus
            $deviceSecureBoot = $deviceHealthAttestation.secureBoot
            $deviceBootDebugging = $deviceHealthAttestation.bootDebugging
            $deviceOsKernelDebugging = $deviceHealthAttestation.operatingSystemKernelDebugging
            $deviceCodeIntegrity = $deviceHealthAttestation.codeIntegrity
            $deviceTestSigning = $deviceHealthAttestation.testSigning
            $deviceSafeMode = $deviceHealthAttestation.safeMode
            $devicesWindowsPE = $deviceHealthAttestation.windowsPE
            $deviceEarlyLaunchAntiMalwareDriverProtection = $deviceHealthAttestation.earlyLaunchAntiMalwareDriverProtection
            $deviceVirtualSecureMode = $deviceHealthAttestation.virtualSecureMode
            $deviceAttestationTpmVer = $deviceHealthAttestation.tpmVersion
            $deviceMemoryIntegrityProtection = $deviceHealthAttestation.memoryIntegrityProtection
            $deviceMemoryAccessProtection = $deviceHealthAttestation.memoryAccessProtection
            $deviceVirtualizationBasedSecurity = $deviceHealthAttestation.virtualizationBasedSecurity
            $deviceFirmwareProtection = $deviceHealthAttestation.firmwareProtection
            $deviceSystemManagementMode = $deviceHealthAttestation.systemManagementMode
            $deviceSecuredCorePC = $deviceHealthAttestation.securedCorePC
            break
        }
    }
    if(!($deviceHealthAttestation))
    {
        $deviceHealthAttestationStatus = "Unknown"
        $deviceHealthAttestationSupportStatus = "Unknown"
        $deviceHealthAttestationKey = "Unknown"
        $deviceBitLockerStatus = "Unknown"
        $deviceSecureBoot = "Unknown"
        $deviceBootDebugging = "Unknown"
        $deviceOsKernelDebugging = "Unknown"
        $deviceCodeIntegrity = "Unknown"
        $deviceTestSigning = "Unknown"
        $deviceSafeMode = "Unknown"
        $devicesWindowsPE = "Unknown"
        $deviceEarlyLaunchAntiMalwareDriverProtection = "Unknown"
        $deviceVirtualSecureMode = "Unknown"
        $deviceAttestationTpmVer = "Unknown"
        $deviceMemoryIntegrityProtection = "Unknown"
        $deviceMemoryAccessProtection = "Unknown"
        $deviceVirtualizationBasedSecurity = "Unknown"
        $deviceFirmwareProtection = "Unknown"
        $deviceSystemManagementMode = "Unknown"
        $deviceSecuredCorePC = "Unknown"
    }

    #MDM over GPO status, if applied
    $deviceMDMoverGPO = $device.preferMdmOverGroupPolicyAppliedDateTime
    if($deviceMDMoverGPO = "0001-01-01T00:00:00Z"){
        $deviceMDMoverGPOstring = "Not applied."
    }
    else
    {
        $deviceMDMoverGPOstring = $deviceMDMoverGPO
    }

    #managed by state (Intune devices query doesn't appear to pull configMgr-only/cloud-attached devices, but including if statement to be safe)
    if($device.managementAgent -eq "configurationManagerClientMdm"){
        $deviceManagement = "Co-Managed"
    }
    elseif($device.managementAgent -eq "mdm")
    {
        $deviceManagement = "Intune"
    }
    elseif($device.managementAgent -eq "configurationManagerClient")
    {
        $deviceManagement = "ConfigMgr"
    }
    else
    {
        $deviceManagement = $device.managementAgent
    }

    #encryption state
    if(($device.isEncrypted) -eq "True"){
        $deviceEncryptionStatus = "Encrypted"
    }
    else
    {
        $deviceEncryptionStatus = "Not encrypted"
    }

    #Search encryption report for matching device
    foreach($erRecord in $encryptionReport)
    {
        if($erRecord.deviceName -eq $deviceName)
        {
            $deviceEncryptionReport_ReadinessState = $erRecord.encryptionReadinessState
            $deviceEncryptionReport_TPMSpecificationVersion = $erRecord.tpmSpecificationVersion
            $deviceEncryptionReport_AdvancedBitLockerStates = $erRecord.advancedBitLockerStates
            break
        }
    }

    #SCCM information for co-managed devices, where applicable
    $deviceSCCMclientHealth = $device.configurationManagerClientHealthState.state
    $deviceSCCMclientLastSync = $device.configurationManagerClientHealthState.lastSyncDateTime
    if($deviceManagement -eq "Intune"){
        $deviceSCCMclientHealth = "Intune-only"
        $deviceSCCMclientSync = "N/A"
    }
    else
    {
        $deviceSCCMclientSync = $deviceSCCMclientLastSync.split("T")[0]     #Will display in UTC
        #$deviceSCCMclientSync = [datetime]::Parse($deviceSCCMclientLastSync).ToString('MM-dd-yyyy')
    }
    $deviceComanagementSettings = $device.configurationManagerClientEnabledFeatures
    $deviceComanagementApps = "N/A"
    $deviceComanagementResourceAccess = "N/A"
    $deviceComanagementDeviceConfig = "N/A"
    $deviceComanagementCompliance = "N/A"
    $deviceComanagementWindowsUpdate = "N/A"
    $deviceComanagementEndpointProtection = "N/A"
    $deviceComanagementOfficeApps = "N/A"
    
    if($deviceManagement -eq "Co-Managed"){
        if($deviceComanagementSettings.ModernApps -eq "True") {$deviceComanagementApps = "Intune"} else {$deviceComanagementApps = "SCCM"}
        if($deviceComanagementSettings.resourceAccess -eq "True") {$deviceComanagementResourceAccess = "Intune"} else {$deviceComanagementResourceAccess = "SCCM"}
        if($deviceComanagementSettings.deviceConfiguration -eq "True") {$deviceComanagementDeviceConfig = "Intune"} else {$deviceComanagementDeviceConfig = "SCCM"}
        if($deviceComanagementSettings.compliancePolicy -eq "True") {$deviceComanagementCompliance = "Intune"} else {$deviceComanagementCompliance = "SCCM"}
        if($deviceComanagementSettings.windowsUpdateForBusiness -eq "True") {$deviceComanagementWindowsUpdate = "Intune"} else {$deviceComanagementWindowsUpdate = "SCCM"}
        if($deviceComanagementSettings.endpointProtection -eq "True") {$deviceComanagementEndpointProtection = "Intune"} else {$deviceComanagementEndpointProtection = "SCCM"}
        if($deviceComanagementSettings.officeApps -eq "True") {$deviceComanagementOfficeApps = "Intune"} else {$deviceComanagementOfficeApps = "SCCM"}
    }

    #logged on users
    $usersLoggedOn = $device.usersLoggedOn.userId

    #Group memberships of device
    write-host "Getting generic device profile of $deviceSerial..."
    $deviceNormalProfile = (Invoke-RestMethod "https://graph.microsoft.com/beta/devices?`$filter=displayName eq '$($deviceName)'" -Method "GET" -Headers $headers).value

    if($null -eq $deviceNormalProfile){
        Write-Warning "Azure device object could not be found."
    }
    elseif($deviceNormalProfile.length -gt 1){

        foreach($object in $deviceNormalProfile){
            if($object.deviceId -eq $device.azureActiveDirectoryDeviceId){
                $deviceAzureId = $object.deviceId
                $deviceAzureObjId = $object.id
                break
            }
        }
    }

    else
    {
        $deviceAzureId = $deviceNormalProfile.deviceId
        $deviceAzureObjId = $deviceNormalProfile.id
    }

    write-host "Getting group memberships of device $deviceSerial..."
    $deviceGroupSearch = Invoke-RestMethod "https://graph.microsoft.com/beta/devices/$($deviceAzureObjId)/memberOf" -Method "GET" -Headers $headers
    $deviceGroupValue = $deviceGroupSearch.value
    $deviceGroups = @()
    $deviceGroupsString = $null

    foreach($group in $deviceGroupValue){
        $deviceGroups += $group.displayName
        $deviceGroupsString = $deviceGroups -join "; "
    }


    #Feature Update Status
    $deviceFeatureUpdateStatus = $null
    foreach($entry in $featureUpdateReport){
        $featUpdate_Status = $entry.CurrentDeviceUpdateSubstatus_loc
        $featUpdate_deviceName = $entry.DeviceName

        if($featUpdate_deviceName -eq $deviceName){
            $deviceFeatureUpdateStatus = $featUpdate_Status
            break
        }
    }

    # get list of all compliance policies of this particular device
    write-host "Getting compliance policy for device $deviceSerial ..."
    $deviceCompliancePolicy = (Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceId')/deviceCompliancePolicyStates" -Method "GET" -Headers $headers).value
    $deviceComplianceStatus_Detailed = $null
    $settingArray = @()
    $complianceArray = @()
    $windowsPolicyFound = $False
    $defaultPolicyFound = $True

    # Compliance policy details (please update line 382 below - this way Intune's default compliance state is not reported)
    foreach($policy in $deviceCompliancePolicy){
        if($policy.platformType -like "*windows*"){

            $windowsPolicyFound = $True
            $deviceComplianceId = $policy.id
            write-host "Getting compliance settings states for device $deviceName..."
            $deviceComplianceStatus_Detailed = (Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceId')/deviceCompliancePolicyStates('$deviceComplianceId')/settingStates" -Method "GET" -Headers $headers).value
            $deviceComplianceStatus_Detailed | Select @{n = 'deviceName'; e = { $deviceName } }, state, setting

            if($deviceComplianceStatus_Detailed.Length -eq 0){
                $complianceArray += "Targeted Compliance Policy not evaluated."
            }

            else
            {
                foreach($setting in $deviceComplianceStatus_Detailed)
                {
                    $settingName = $setting.setting
                    $settingName = $settingName.Split(".") | Select -Index 1
                    $settingState = $setting.state
                    $settingUPN = $setting.userPrincipalName

                    if($settingArray -notcontains "($settingUPN) $settingName = $settingState"){
                        $settingArray += "($settingUPN) $settingName = $settingState"
                    }
                }

                #Only include UPN based states if system and UPN states are present 
                foreach($result in $settingArray){
                    if($result -like "*System account*" -and $settingArray -like "*@*"){
                        continue
                    }
                    elseif($complianceArray -contains $result){
                        continue
                    }
                    else
                    {
                        $complianceArray += $result
                    }
                }

            }
        }
        elseif($policy.displayName -like "Default Device Compliance Policy")
        {
            $defaultPolicyFound = $true
            $deviceComplianceId = $policy.id
            write-host "Getting compliance settings states for device $deviceName..."
            $deviceComplianceStatus_Detailed = (Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceId')/deviceCompliancePolicyStates('$deviceComplianceId')/settingStates" -Method "GET" -Headers $headers).value
            $deviceComplianceStatus_Detailed | Select @{n = 'deviceName'; e = { $deviceName } }, state, setting

            if($deviceComplianceStatus_Detailed.Length -eq 0){
                $complianceArray += "Default Compliance Policy not evaluated."
            }

            else
            {
                foreach($setting in $deviceComplianceStatus_Detailed)
                {
                    $settingName = $setting.setting
                    $settingName = $settingName.Split(".") | Select -Index 1
                    $settingState = $setting.state
                    $settingUPN = $setting.userPrincipalName

                    if($settingArray -notcontains "($settingUPN) $settingName = $settingState"){
                        $settingArray += "($settingUPN) $settingName = $settingState"
                    }
                }

                #Only include UPN based states if system and UPN states are present 
                foreach($result in $settingArray){
                    if($result -like "*System account*" -and $settingArray -like "*@*"){
                        continue
                    }
                    elseif($complianceArray -contains $result){
                        continue
                    }
                    else
                    {
                        $complianceArray += $result
                    }
                }

            }
        }

        #Combine compliance results into single string
        $deviceComplianceStatus_DetailedString = $complianceArray -join "; "
    }

    if($windowsPolicyFound -eq $False){
        $deviceComplianceStatus_DetailedString = 'Windows-based Compliance Policy not assigned.'
    }

    #Device Update Ring Status
    foreach($ring in $updateRingsStatus)
    {
        if($($ring.Device) -eq $deviceName)
        {
            $deviceUpdateRing = $($ring.Ring)
            $deviceUpdateRingStatus = $($ring.Status)
            break
        }
    }

    #############################################################

    #Add desired labels and variables to array for csv export
    $record = [ordered] @{
        'Name' = $deviceName
        'Serial' = $deviceSerial
        'Associate UPN' = $deviceUPN
        'Last Device Sync Time' = $deviceSync
        'Managed By' = $deviceManagement
        'OS Version' = $deviceOsVersion
        'OS Edition' = $deviceOsEdition
        'Feature Update Status' = $deviceFeatureUpdateStatus
        'Update Ring' = $deviceUpdateRing
        'Update Ring Status' = $deviceUpdateRingStatus
        'Encryption Status' = $deviceEncryptionStatus
        'BitLocker Status' = $deviceBitLockerStatus
        'Encryption Readiness State' = $deviceEncryptionReport_ReadinessState
        'Encryption Advanced State' = $deviceEncryptionReport_AdvancedBitLockerStates
        'TPM SpecVersion' = $deviceTpmSpecVersion
        'TPM SpecVersion (H.A.)' = $deviceAttestationTpmVer
        'TPM Manufacturer' = $deviceTpmManufacturer
        'TPM Mfr Version' = $deviceTpmMfrVersion
        'BIOS Version' = $deviceBiosVersion
        'Secure Boot' = $deviceSecureBoot
        'Model' = $deviceModel
        'Manufacturer' = $deviceManufacturer
        'Is Virtual Machine' = $deviceSecurityisVirtualMachine
        'Chassis Type' = $deviceChassis
        'Processor Architecture' = $deviceArchitecture
        'Compliance Status' = $deviceCompliance
        'Detailed Compliance Settings' = $deviceComplianceStatus_DetailedString
        'SCCM Client Health' = $deviceSCCMclientHealth
        'SCCM Client Last Sync' = $deviceSCCMclientSync
        'Co-Management: Compliance' = $deviceComanagementCompliance
        'Co-Management: Device Configuration' = $deviceComanagementDeviceConfig
        'Co-Management: Endpoint Protection' = $deviceComanagementEndpointProtection
        'Co-Management: Resource Access' = $deviceComanagementResourceAccess
        'Co-Management: Client Apps' = $deviceComanagementApps
        'Co-Management: Office C2R Apps' = $deviceComanagementOfficeApps
        'Co-Management: Windows Updates' = $deviceComanagementWindowsUpdate
        'MDM over GPO Applied' = $deviceMDMoverGPOstring
        'Intune Device ID' = $deviceId
        'Azure Device ID' = $deviceAzureId
        'Scope Tags' = $deviceScopeTags
        'Group Memberships' = $deviceGroupsString
        'Users Logged On' = $usersLoggedOn
        'IP Address' = $deviceIpAddress
        'IP Subnet' = $deviceIpSubnet
        'Wired IP Address' = $deviceWiredIpAddress
        'Ethernet Mac Address' = $deviceEthernetMacAddress
        'Total Storage' = $deviceTotalStorage
        'Free Storage' = $deviceFreeStorage
        'Health Attestation Status' = $deviceHealthAttestationStatus
        'Health Attestation Support' = $deviceHealthAttestationSupportStatus
    }

    $outarray += New-Object PsObject -property $record

    #Each device sets off 6 calls.  1500 devices is 9000 calls.  Rest for 10 seconds.  Process time for one device is estimated at 1-2 seconds.
    #This means 1500 devices take approximately 1500 seconds, or 25 minutes.  Graph limit window is 10,000 calls per 10 minutes.  Resting is to make the window absolute and to not interfere in company business.
    #
    if($deviceCount % 1500 -eq 0)
    {
        Write-Output "$deviceCount devices have been processed so far.  Now sleeping for 10 seconds to avoid graph limiting..."
        Start-Sleep -Seconds 10
        Write-Host "Re-authenticating with app registration..."
        $headers = Connect_To_Graph


        #NOTE: This if statement can be used if you need to re-authenticate after a larger number of devices (needs to be a multiple of the number above)
        <#if($deviceCount % 3000 -eq 0)
        {
            Write-Host "Re-authenticating with app registration..."
            $headers = Connect_To_Graph
        }
        #>
    }

}


#Finally, we export the Data :)
Write-Host "Reporting Complete. Exporting the final csv..."
$outarray | export-csv "C:\Users\Public\Desktop\Intune_WindowsPCs_$($targetDeviceGroupName)_Report.csv" -NoTypeInformation -Force 
