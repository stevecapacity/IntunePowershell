reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "SearchOnTaskbarMode" /t REG_DWORD /d 1 /f | Out-Host

Start-Sleep -seconds 1

stop-process -name explorer -Force