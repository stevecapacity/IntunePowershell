Install-PackageProvider -Name NuGet -Force
Install-Module -Name PowerShellGet -Force -AllowClobber

Remove-Module PowerShellGet,PackageManagement -Force

Import-Module PowerShellGet -MinimumVersion 2.0 -Force
Import-PackageProvider PowerShellGet -MinimumVersion 2.0 -Force

$requiredModules = @(
    "Microsoft.Graph.DirectoryObjects",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Users.Actions",
    "Microsoft.Graph.Users.Functions",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Governance",
    "Microsoft.Graph.Applications"
)

foreach($module in $requiredModules)
{
    if(!(Get-Module -Name $module -ListAvailable))
    {
        Install-Module -Name $module -Force -AllowClobber
    }
}

Install-Module -Name Microsoft.Graph.Entra -Repository PSGallery -Force -AllowPreRelease