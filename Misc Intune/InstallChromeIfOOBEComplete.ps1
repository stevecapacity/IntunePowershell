$Definition = @"

using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Api
{
    public class Kernel32
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int OOBEComplete(ref int bIsOOBEComplete);
    }
}
"@

function log
{
    Param(
        [string]$message
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    $output = "$time - $message"
    Write-Output $output
}

Add-Type -TypeDefinition $Definition -Language CSharp

$IsOOBEComplete = $false
[void][Api.Kernel32]::OOBEComplete([ref] $IsOOBEComplete)

$logFile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ChromeInstaller.log"

if(-not(Test-Path $logFile))
{
    New-Item -Path $logFile -ItemType File -Force | Out-Null
}

Start-Transcript -Path $logFile -Verbose -Append

log "IsOOBEComplete variable is equal to $($IsOOBEComplete)"

if(-not $IsOOBEComplete)
{
    log "OOBE is not complete. Skipping Chrome install."
    Exit 0 # Intune will retry later
}

log "OOBE complete. Installing Chrome..."

Start-Process -FilePath "$($PSScriptRoot)\GoogleChromeStandaloneEnterprise64.msi" -ArgumentList "/qn" -Wait -NoNewWindow

log "Chrome installation completed."

Stop-Transcript
Exit 0
