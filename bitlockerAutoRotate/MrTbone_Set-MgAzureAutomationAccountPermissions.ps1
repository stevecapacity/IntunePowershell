<#PSScriptInfo
.SYNOPSIS
    Script for setting permissions on Azure Automation Accounts 
 
.DESCRIPTION
    This script will assign specified permissions on an Azure Automation Account
        
.EXAMPLE
   .\Set-MgAzureAutomationAccountPermissions.ps1
    will assign specified permissions on an Azure Automation Account with settings in the modifyable region. 

.NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    1.0

.RELEASENOTES
    1.0 2024-01-04 Initial Build

.AUTHOR
    Tbone Granheden 
    @MrTbone_se

.COMPANYNAME 
    Coligo AB

.GUID 
    00000000-0000-0000-0000-000000000000

.COPYRIGHT
    Feel free to use this, But would be grateful if My name is mentioned in Notes 

.CHANGELOG
    1.0.2401.1 - Initial Version
#>

#region ---------------------------------------------------[Set script requirements]-----------------------------------------------
#endregion

#region ---------------------------------------------------[Script Parameters]-----------------------------------------------
#endregion

#region ---------------------------------------------------[Modifiable Parameters and defaults]------------------------------------
$TenantID = "d6f19297-08a2-4ade-9a68-0db7586d80ad"
$ManagedIdentity = "Tbone-IntuneAutomation"
    $Permissions = @(
    "DeviceManagementManagedDevices.ReadWrite.All"
    "AuditLog.Read.All"
    "User.Read.All"
)
#endregion

#region ---------------------------------------------------[Static Variables]------------------------------------------------------
    $GraphAppId = "00000003-0000-0000-c000-000000000000" # Don't change this.
    $AdminPermissions = @("Application.Read.All","AppRoleAssignment.ReadWrite.All")   # To be able to set persmissions on the Managed Identity
#endregion

#region ---------------------------------------------------[Import Modules and Extensions]-----------------------------------------
import-module Microsoft.Graph.Authentication
import-module Microsoft.Graph.Applications
#endregion

#region ---------------------------------------------------[Functions]------------------------------------------------------------
#endregion

#region ---------------------------------------------------[[Script Execution]------------------------------------------------------
Connect-MgGraph -TenantId $TenantId -Scopes $AdminPermissions
$IdentityServicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq '$managedidentity'"
$GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
$AppRoles = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -in $Permissions -and $_.AllowedMemberTypes -contains "Application"}
    
foreach($AppRole in $AppRoles)
 {
  $AppRoleAssignment = @{
      "PrincipalId" = $IdentityServicePrincipal.Id
      "ResourceId" = $GraphServicePrincipal.Id
      "AppRoleId" = $AppRole.Id
    }
  New-MgServicePrincipalAppRoleAssignment `
      -ServicePrincipalId $AppRoleAssignment.PrincipalId `
      -BodyParameter $AppRoleAssignment `
      -Verbose
  }
disconnect-mggraph