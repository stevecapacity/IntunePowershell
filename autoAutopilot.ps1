 # AUTHENTICATE TO MS GRAPH
 $clientId = "<CLIENT_ID>"
 $clientSecret = "<CLIENT_SECRET>"
 $tenantId = "<TEANANT_ID>"
 
 $tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oath2/v2.0/token"
 $tokenRequestBody = @{
     client_id = $clientId
     client_secret = $clientSecret
     scope = "https://graph.microsoft.com/.default"
     grant_type = "client_credentials"
 }
 
 $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenRequestBody
 $accessToken = $tokenResponse.access_token
 
 $headers = @{
     "Authorization" = "Bearer $accessToken"
 }
 
 
 
 # GET HARDWARE INFO
 $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
 $hardwareId = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
 $groupTag = "M365"
 
 # CONSTRUCT JSON
 $json = @"
 {
    "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
     "groupTag":"$groupTag",
     "serialNumber":"$serialNumber",
     "productKey":"",
     "hardwareIdentifier":"$hardwareId",
     "assignedUserPrincipalName":"",
     "state":{
         "@odata.type":"microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
         "deviceImportStatus":"pending",
         "deviceRegistrationId":"",
         "deviceErrorCode":0,
         "deviceErrorName":""
     }
    }
"@
 
 # POST DEVICE
 Invoke-RestMethod -Method Post -Body $json -ContentType "application/json" -Uri "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities" -Headers $headers
