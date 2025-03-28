function log()
{
    Param(
        [string]$message
    )
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    Write-Output "$date - $message"
}

Start-Transcript -Path "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\fontInstall.log" -Force -Verbose

# Get the fonts in the 'FONT' folder
$fonts = Get-ChildItem -Path ".\Fonts"

# Set the font REGPATH
$regpath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"

# Set font values for each font
foreach($font in $fonts)
{
    $basename = $font.basename
    $extension = $font.extension
    $fullname = $font.fullname
    $fontname = $font.name
    if($extension -eq ".ttf")
    {
        $fontValue = $basename + " (TrueType)"
        log "Font value is $fontvalue"
    }
    if([string]::IsNullOrEmpty($fontValue))
    {
        log "Font not found"
    }
    else
    {
        if(Test-Path "C:\Windows\fonts\$fontname")
        {
            log "Font $fontname already exists"
        }
        else
        {
            Copy-Item -Path $fullname -Destination "C:\Windows\Fonts" -Force
            log "Copied $fullname to C:\Windows\Fonts..."
            reg.exe add $regpath /v $fontValue /t REG_SZ /d $fontname /f | Out-Host
            log "Added $fontValue to registry"
        }
    }
}

Stop-Transcript