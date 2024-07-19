#Get the Username of the User executing the Script

$user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object Username).Username

 #Get the User Executing the Script in NTAccount Security Principal Format

$identityReference = [System.Security.Principal.NTAccount]::new($user)

 #Define the CrowdStrike Driver Folder

[string]$driverFolder = "C:\Windows\System32\drivers\CrowdStrike"

 If (Test-Path $driverFolder) 
 {

    $files = Get-ChildItem -Path $driverFolder -Recurse -Filter "*CD-00000291*.sys" 
    foreach($file in $files)
    {
        $acl = $file.FullName | Get-Acl
        $acl.SetOwner($identityReference)
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$identityReference","FullControl","ContainerInherit,ObjectInherit","None" ,"Allow")
        $acl.SetAccessRule($AccessRule)
        Set-Acl -Path $file.FullName -AclObject $acl
        Remove-Item -Path $file.FullName -Force
    }
}