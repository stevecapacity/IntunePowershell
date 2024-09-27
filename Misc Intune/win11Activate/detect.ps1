# Get the license status 

$licenseStatus = Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object { $_.PartialProductKey } | Select-Object -ExpandProperty LicenseStatus

# If the license status is 1, the OS is activated
if ($licenseStatus -eq 1)
{
    Write-Output "Activated"
    Exit 0
}
else
{
    Write-Output "Not Activated"
    Exit 1
}