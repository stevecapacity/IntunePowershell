# Basic Configuration
$WUKeys = @{
    AU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    WU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
}

$Critical = @('NoAutoUpdate', 'UseWUServer', 'DisableDualScan')
$Audit = @('DoNotConnectToWindowsUpdateInternetLocations', 'SetPolicyDrivenUpdateSourceForDriverUpdates', 'SetPolicyDrivenUpdateSourceForOtherUpdates', 'SetPolicyDrivenUpdateSourceForQualityUpdates', 'SetPolicyDrivenUpdateSourceForFeatureUpdates', 'DisableWindowsUpdateAccess', 'WUServer', 'TargetGroup', 'WUStatusServer', 'TargetGroupEnable')

$Result = @{
    Issues = @()
    Status = 'Healthy'
}

# Registry Properties
function Get-RegValue {
    param(
        [string]$Path,
        [string]$Property,
        [object]$ExpectedValue
    )
    try {
        $val = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Property
        if ($null -ne $val) {
            return @{
                Exists = $true
                Value = $val
                MatchesExpected = ($PSBoundParameters.ContainsKey('ExpectedValue') -and $val -eq $ExpectedValue)
            }
        } else {
            return @{ Exists = $false }
        }
    } catch {
        return @{ Exists = $false }
    }
}

# Test Windows Update Service
function Test-WUService {
    try {
        $mgr = New-Object -ComObject 'Microsoft.Update.ServiceManager'
        $svc = $mgr.Services | Where-Object { $_.Name -eq 'Microsoft Update' }
        if ($svc) {
            return @{
                IsDefault = $svc.IsDefaultAUService
            }
        } else {
            return @{ IsDefault = $false }
        }
    }
    catch {
        return @{ IsDefault = $false }
    }
}

# Detection logic
foreach($s in $Critical) {
    $path = if ($s -eq 'DisableDualScan') {
        $WUKeys.WU
    } else {
        $WUKeys.AU
    }
    $r = Get-RegValue -Path $path -Property $s -ExpectedValue 0
    if ($r.Exists -and $r.Value -eq 1) {
        $Result.Issues += "$s = 1"
        $Result.Status = 'RequiresRemediation'
    }
}

$UseUpdateClass = Get-RegValue -Path $WUKeys.AU -Property 'UseUpdateClassPolicySource' -ExpectedValue 1
if (-not $UseUpdateClass.Exists -or $UseUpdateClass.Value -ne 1) {
    $Result.Issues += 'UseUpdateClassPolicySource misconfigured or missing'
    $Result.Status = 'RequiresRemediation'
}

$WUService = Test-WUService
if (-not $WUService.IsDefault) {
    $Result.Status = 'RequiresRemediation'
}

foreach ($a in $Audit) {
    $chk = Get-RegValue -Path $WUKeys.WU -Property $a
    if ($chk.Exists) {
        Write-Host " $a = $($chk.Value)"
    }
}

# Exit summary
if ($Result.Status -eq 'RequiresRemediation') {
    exit 1
} else {
    exit 0
}