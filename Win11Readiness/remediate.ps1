# Configuration

$WU = @{
    AU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    WU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
}

$ToReset = @(
    @{ P='WU'; N='DoNotConnectToWindowsUpdateInternetLocations'; V=0 }
    @{ P='WU'; N='DisableDualScan'; V=0 },
    @{ P='WU'; N='SetPolicyDrivenUpdateSourceForDriverUpdates'; V=0 },
    @{ P='WU'; N='SetPolicyDrivenUpdateSourceForOtherUpdates'; V=0 },
    @{ P='WU'; N='SetPolicyDrivenUpdateSourceForQualityUpdates'; V=0 },
    @{ P='WU'; N='SetPolicyDrivenUpdateSourceForFeatureUpdates'; V=0 },
    @{ P='WU'; N='DisableWindowsUpdateAccess'; V=0 },
    @{ P='AU'; N='NoAutoUpdate'; V=0 },
    @{ P='AU'; N='UseWUServer'; V=0 },
    @{ P='AU'; N='UseUpdateClassPolicySource'; V=1 }
)

$ToRemove = @('WUServer', 'WUStatusServer', 'TargetGroup', 'TargetGroupEnabled')

# Function to set value
function Set-Value {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        $curr = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Name
        if ($curr -ne $Value) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
        }
    }
    catch {
        Write-Host "$($_.Exception.Message)"
    }
}

# Function to remove reg key
function Remove-Value {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        if ((Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains $Name) {
            Remove-ItemProperty -Path $Path -Name $Name -Force
        }
    }
    catch {
        Write-Host "$($_.Exception.Message)"
    }
}

# Function to restart services
function Restart-WU {
    foreach ($svc in 'wuauserv', 'bits', 'dosvc') {
        try {
            Restart-Service $svc -Force -ErrorAction Stop
        } catch {
            Write-Host "$($_.Exception.Message)"
        }
    }
}

# Function to trigger Update scan
function Trigger-Scan {
    $uso = "$env:SystemRoot\System32\usoclient.exe"
    if (Test-Path $uso) {
        try {
            Start-Process $uso -ArgumentList 'StartInteractiveScan' -Wait -NoNewWindow
        }
        catch {
            Write-Host "$($_.Exception.Message)"
        }
    }
}

# Reset registry settings
foreach ($s in $ToReset) {
    Set-Value -Path $WU[$s.P] -Name $s.N -Value $s.V
}

# Remove WSUS keys
foreach ($r in $ToRemove) {
    Remove-Value -Path $WU.WU -Name $r
}

# Restart services and trigger scan
Restart-WU
Trigger-Scan

exit 0