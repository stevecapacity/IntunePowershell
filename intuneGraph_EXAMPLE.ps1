function Filter-Intune($emailAddress,$OSVersion)
{
  if($emailAddress -ne $null)
  {
    $intuneDevices = Get-MgDeviceManagementManagedDevices | Where-Object {$_.EmailAddress -eq "$($emailAddress)"}
    if($intuneDevices.Count -gt 0)
    {
      $userDevices = $intuneDevices | Select-Object DisplayName,OSVersion
     if($osVersion -ne $null)
     {
       $selectedDevices = $userDevices | Where-Object {$_.OSVersion -match "$($OSVersion)"}
       return $selectedDevices
     }
     else
     {
       $selectedDevices = $userDevices
       return $userDevices
     }
    }
    else
    {
      Write-Host "No device found associated with $($emailAddress)"
    }
  }
  else
  {
    Write-Host "No email address provided to function
  }
}
