# comfort settings

# taskbar alignment
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Host
# windows search
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v SearchOnTaskbarMode /t REG_DWORD /d 1 /f | Out-Host
# right click
reg.exe add "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve /reg:64 | Out-Host
# wallpaper
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v Wallpaper /t REG_SZ /d "C:\Work\ninjaCat.jpg" /f | Out-Host
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v WallpaperStyle /t REG_DWORD /d 4 /f | Out-Host

Stop-Process -name explorer -force
# my apps

Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

$apps = @(
    "notepadplusplus.install",
    "vscode",
    "7zip.install",
    "firefox",
    "vlc"
)

foreach($app in $apps)
{
    choco install $app -y
}
# notepad++
# vscode
# vlc
# firefox