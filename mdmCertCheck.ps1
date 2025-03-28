# PowerShell Script to Check for Intune Device Certificate

# Define the certificate store location
$certStore = "Cert:\LocalMachine\My"

# Search criteria: Common name or issuer name for Intune certificate
$searchCriteria = "Microsoft Intune MDM Device CA"

# Get certificates from the specified store
Write-Host "Searching for Intune Device Certificates in $certStore..."
$certificates = Get-ChildItem -Path $certStore | Where-Object {
    $_.Issuer -like "*$searchCriteria*" -or $_.Subject -like "*$searchCriteria*"
}

if ($certificates) {
    Write-Host "Found Intune Device Certificate(s):" -ForegroundColor Green
    foreach ($cert in $certificates) {
        Write-Host "Subject: $($cert.Subject)"
        Write-Host "Issuer: $($cert.Issuer)"
        Write-Host "Thumbprint: $($cert.Thumbprint)"
        Write-Host "Not Before: $($cert.NotBefore)"
        Write-Host "Not After: $($cert.NotAfter)"
        Write-Host "-----------------------------------------"
    }
} else {
    Write-Host "No Intune Device Certificate found." -ForegroundColor Red
}

# Check if any certificate is valid
$validCertificates = $certificates | Where-Object {
    $_.NotAfter -gt (Get-Date) -and $_.NotBefore -lt (Get-Date)
}

if ($validCertificates) {
    Write-Host "Valid Intune Device Certificate(s) Found:" -ForegroundColor Green
    foreach ($cert in $validCertificates) {
        Write-Host "Subject: $($cert.Subject)"
        Write-Host "Expires On: $($cert.NotAfter)"
    }
} else {
    Write
