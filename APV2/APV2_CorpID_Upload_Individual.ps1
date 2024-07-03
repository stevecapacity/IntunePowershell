# Install and import the Microsoft.Graph.Beta.DeviceManagement module
Install-Module Microsoft.Graph.Beta.DeviceManagement -confirm:$false -Force -AllowClobber
Import-Module Microsoft.Graph.Beta.DeviceManagement

# Connect to Microsoft Graph
Connect-MgGraph

# Get the computer system and BIOS information
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS

# Create the JSON payload
$params = @{
    overwriteImportedDeviceIdentities = $false
	importedDeviceIdentities = @(
		@{
			importedDeviceIdentityType = "manufacturerModelSerial"
			importedDeviceIdentifier = "$($computerSystem.Manufacturer),$($computerSystem.Model),$($bios.SerialNumber)"
		}
	)
} | ConvertTo-Json

# Upload the device identity
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/importedDeviceIdentities/importDeviceIdentityList" -Body $params