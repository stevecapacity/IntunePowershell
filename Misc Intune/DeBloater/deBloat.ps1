$bloatApps = @(
    "Microsoft.XboxApp",
    "Clipchamp.Clipchamp",
    "Microsoft.MSPaint",
    "Microsoft.MicrosoftSolitaireCollection"
)

foreach($app in $bloatApps)
{
    $installed = (Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq "$($app)"})
    if($installed)
    {
        try {
            $installed | Remove-AppxProvisionedPackage -Online
        }
        catch {
            $message = $_
            Write-Host "Error removing $($app): $message"
        }
    }
}