 #Script written by Jesse Weimer and Logan Lautt - GetRubix

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
$TARGET_UPDATE_PROFILE = "All"

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

#DELEGATED PERMISSIONS CONNECTION

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Web

function Connect_To_Graph {
    $tenant = "primary-or-federated-tenant"
    $clientId = "client-app-id"

    $AccessToken = Get-MsalToken -TenantId $tenant -ClientId $clientId -ForceRefresh
    $authHeader = $AccessToken.CreateAuthorizationHeader()

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($authHeader)")
    $headers.Add("Accept", "application/json")

    $headers
    Start-Sleep -Seconds 3
}

$headers = Connect_To_Graph

<#
#APPLICATION-BASED PERMISSIONS CONNECTION (replace 54-69 above)

function Connect_To_Graph {
    #App registration (Needs the application-based permission DeviceManagementServiceConfig.ReadWrite.All)
    $tenant = "primary-or-federated-domain"
    $clientId = "client-app-id"
    $clientSecret = "secret-value"
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
#>

#############################################################
#############################################################

# Start gathering all Intune Windows devices records
$intuneDevices = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'" -Headers $headers -Verb

# Get Windows Update remediation statuses
$remediation1 = "first-remediation-object-id"
$remediation2 = "second-remediation-object-id"
$remediationStatus_WinUpdate = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($remediation1)/deviceRunStates" -Headers $headers
$remediationStatus_WinUpdateAU = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($remediation2)/deviceRunStates" -Headers $headers

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


# Get Device Health Attestation Report details
Write-Host "Getting Device Health Attestation Report..."
$deviceHealthAttestationReport = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=isof('microsoft.graph.windowsManagedDevice')&`$select=deviceHealthAttestationState,deviceName,operatingSystem,id" -Headers $headers -Verb

# Get Encryption Report
Write-Host "Getting Encryption Report..."
$encryptionReport = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDeviceEncryptionStates?`$select=advancedBitLockerStates,deviceName,encryptionReadinessState" -Headers $headers -Verb


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


# WIndows 11 Hardware Readiness (from Endpoint Analytics)
$win11Readiness = Get-GraphPagedResult -Uri "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsWorkFromAnywhereMetrics('allDevices')/metricDevices?`$select=id,deviceName,osDescription,osVersion,upgradeEligibility,azureAdJoinType,ramCheckFailed,storageCheckFailed,processorCoreCountCheckFailed,processorSpeedCheckFailed,tpmCheckFailed,secureBootCheckFailed,processorFamilyCheckFailed,processor64BitCheckFailed,osCheckFailed&dtfilter=all" -Headers $headers -Verb


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
    
    #DEVICE VARIABLES FOR REPORTING
    $deviceId = $device.id
    $deviceAADid = $device.azureActiveDirectoryDeviceId
    $deviceName = $device.deviceName
    $deviceLastSync = $device.lastSyncDateTime
    $deviceSync = $deviceLastSync.split("T")[0]  #This will be in UTC
    $deviceUPN = $device.userPrincipalName
    $deviceOsVersion = $device.osVersion
    $deviceCompliance = $device.complianceState
    $deviceJoinType = $device.joinType
    $deviceEnrollmentType = $device.deviceEnrollmentType
    $deviceAutopilotEnrolled = $device.autopilotEnrolled
    $deviceEnrollmentProfileName = $device.enrollmentProfileName
    $deviceIsEncrypted = $device.isEncrypted
    $deviceModel = $device.model
    $deviceManufacturer = $device.manufacturer
    $deviceSerial = $device.serialNumber
    $deviceWifiMacAddress = $device.wiFiMacAddress

    #Additional call for hardware details...
    $deviceAdditionalInfo = Invoke-RestMethod "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($deviceId)?`$select=chassisType,ethernetMacAddress,hardwareInformation,physicalMemoryInBytes,processorArchitecture,roleScopeTagIds" -Method "GET" -Headers $headers
    $deviceHardwareInfo = $deviceAdditionalInfo.hardwareInformation
    [string]$deviceScopeTags = $deviceAdditionalInfo.roleScopeTagIds
    $deviceChassis = $deviceAdditionalInfo.chassisType
    $deviceBiosVersion = $deviceHardwareInfo.systemManagementBIOSVersion
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

    #managed by state (Intune devices query doesn't appear to pull configMgr-only/cloud-attached devices)
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

    #Win11 Upgrade Hardware Readiness
    $deviceWin11HardwareReadiness = $null
    $deviceWin11HardwareReadiness = $win11Readiness | Where-Object {$_.id -eq $deviceId}
    if($deviceWin11HardwareReadiness)
    {
        $deviceWin11HardwareReadiness_eligibility = $deviceWin11HardwareReadiness.upgradeEligibility
        $deviceWin11HardwareReadiness_ramCheckFailed = $deviceWin11HardwareReadiness.ramCheckFailed
        $deviceWin11HardwareReadiness_storageCheckFailed = $deviceWin11HardwareReadiness.storageCheckFailed
        $deviceWin11HardwareReadiness_processorCoreCountCheckFailed = $deviceWin11HardwareReadiness.processorCoreCountCheckFailed
        $deviceWin11HardwareReadiness_processorSpeedCheckFailed = $deviceWin11HardwareReadiness.processorSpeedCheckFailed
        $deviceWin11HardwareReadiness_tpmCheckFailed = $deviceWin11HardwareReadiness.tpmCheckFailed
        $deviceWin11HardwareReadiness_secureBootCheckFailed = $deviceWin11HardwareReadiness.secureBootCheckFailed
        $deviceWin11HardwareReadiness_processorFamilyCheckFailed = $deviceWin11HardwareReadiness.processorFamilyCheckFailed
        $deviceWin11HardwareReadiness_processor64BitCheckFailed = $deviceWin11HardwareReadiness.processor64BitCheckFailed
        $deviceWin11HardwareReadiness_osCheckFailed = $deviceWin11HardwareReadiness.osCheckFailed
    }
    else
    {
        $deviceWin11HardwareReadiness_eligibility = "No data"
        $deviceWin11HardwareReadiness_ramCheckFailed = "No data"
        $deviceWin11HardwareReadiness_storageCheckFailed = "No data"
        $deviceWin11HardwareReadiness_processorCoreCountCheckFailed = "No data"
        $deviceWin11HardwareReadiness_processorSpeedCheckFailed = "No data"
        $deviceWin11HardwareReadiness_tpmCheckFailed = "No data"
        $deviceWin11HardwareReadiness_secureBootCheckFailed = "No data"
        $deviceWin11HardwareReadiness_processorFamilyCheckFailed = "No data"
        $deviceWin11HardwareReadiness_processor64BitCheckFailed = "No data"
        $deviceWin11HardwareReadiness_osCheckFailed = "No data"
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

    ### INTUNE REMEDIATIONS ###

    #WindowsUpdate AU
    $deviceRemediationStatus_WinUpdate = ($remediationStatus_WinUpdate | Where-Object {$_.id -match $deviceId}).preRemediationDetectionScriptOutput
    #WindowsUpdate
    $deviceRemediationStatus_WinUpdateAU = ($remediationStatus_WinUpdateAU | Where-Object {$_.id -match $deviceId}).preRemediationDetectionScriptOutput


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

    #logged on users
    $usersLoggedOn = $device.usersLoggedOn.userId

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
        'W11 Readiness Status' = $deviceWin11HardwareReadiness_eligibility
        'W11 RAM Check Failed' = $deviceWin11HardwareReadiness_ramCheckFailed
        'W11 Storage Check Failed' = $deviceWin11HardwareReadiness_storageCheckFailed
        'W11 Core Processor Count Failed' = $deviceWin11HardwareReadiness_processorCoreCountCheckFailed
        'W11 Processor Speed Failed' = $deviceWin11HardwareReadiness_processorSpeedCheckFailed
        'W11 TPM Check Failed' = $deviceWin11HardwareReadiness_tpmCheckFailed
        'W11 Secure Boot Check Failed' = $deviceWin11HardwareReadiness_secureBootCheckFailed
        'W11 Processor Family Failed' = $deviceWin11HardwareReadiness_processorFamilyCheckFailed
        'W11 Processor 64Bit Failed' = $deviceWin11HardwareReadiness_processor64BitCheckFailed
        'W11 OS Check Failed' = $deviceWin11HardwareReadiness_osCheckFailed
        'Encryption Status' = $deviceEncryptionStatus
        'TPM SpecVersion' = $deviceTpmSpecVersion
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
        'WinUpdate GPO Registry' = $deviceRemediationStatus_WinUpdate
        'WinUpdate_AU GPO Registry' = $deviceRemediationStatus_WinUpdateAU
        'Intune Device ID' = $deviceId
        'Azure Device ID' = $deviceAzureId
        'Group Memberships' = $deviceGroupsString
        'Users Logged On' = $usersLoggedOn
        'IP Address' = $deviceIpAddress
        'IP Subnet' = $deviceIpSubnet
        'IP Address Wired' = $deviceWiredIpAddress
        'Wireless Mac Address' = $deviceWifiMacAddress
        'Ethernet Mac Address' = $deviceEthernetMacAddress
        'Total Storage' = $deviceTotalStorage
        'Free Storage' = $deviceFreeStorage
    }

    $outarray += New-Object PsObject -property $record

    #Pause to avoid throttling, and re-authenticate
    if($deviceCount % 1500 -eq 0)
    {
        Write-Output "$deviceCount devices have been processed so far.  Now sleeping for 10 seconds to avoid graph limiting..."
        Start-Sleep -Seconds 15
        Write-Host "Re-authenticating with app registration..."
        $headers = Connect_To_Graph
    }
}


#Finally, we export the Data :)
Write-Host "Reporting Complete. Exporting the final csv..."
$outarray | export-csv "C:\Users\Public\Desktop\Intune_WindowsPCs_$($targetDeviceGroupName)_Report.csv" -NoTypeInformation -Force 
