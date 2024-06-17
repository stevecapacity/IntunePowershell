try
{
    Get-AppxPackage -Name "MicrosoftTeams" -AllUsers | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq "MicrosoftTeams"} | Remove-AppxProvisionedPackage -Online
    Write-Host "Removed personal Teams"
    Exit 0
}
catch
{
    $message = $_.Exception.Message
    Write-Host "Failed to remove personal Teams: $message"
    Exit 1
}