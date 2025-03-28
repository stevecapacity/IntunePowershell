Start-Process "reagentc.exe" -ArgumentList "/disable"

Start-Sleep -Seconds 5

Get-Partition | Where-Object -FilterScript {$_.Type -eq "Recovery"} | Remove-Partition -Confirm:$false


Start-Sleep -Seconds 5

diskpart /s ".\recovery.txt"

Start-Sleep -Seconds 5

mkdir "Z:\Recovery\WindowsRE"

Start-Sleep -Seconds 2

Copy-Item "$($psscriptroot)\Winre.wim" "Z:\Recovery\WindowsRE"

Start-Process "reagentc.exe" -ArgumentList '/SetREimage /Path "Z:\Recovery\WindowsRE"'

Start-Sleep -Seconds 5

Start-Process "reagentc.exe" -ArgumentList '/enable'

$partitionNumber = Get-Partition | Where-Object -FilterScript {$_.Type -eq "Recovery"} | Select-Object -ExpandProperty PartitionNumber

(Get-Content "$($psscriptroot)\unmount.txt") | ForEach-Object {$_ -replace "<x>", "$partitionNumber"} | Set-Content "$($psscriptroot)\unmount.txt"

Start-Sleep -Seconds 2

diskpart /s ".\unmount.txt"