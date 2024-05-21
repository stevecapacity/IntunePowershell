# Script components: do not run as full script
# These are meant to be added to the intune migration solution

# Change wallpaper after first reboot during middleBoot sequence.
# Add the below section to 'startMigrate.ps1'

$regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
$imgPath = "path\ToYour\Migration\Image.jpg"

reg.exe add $regPath /v LockScreenImagePath /t REG_SZ /d $imgPath /f
reg.exe add $regPath /v LockScreenImageUrl /t REG_SZ /d $imgPath /f
reg.exe add $regPath /v LockScreenImageStatus /t REG_DWORD /d 1 /f

# The next section will set the Lock screen wallpaper to the corporate image
# The below should be added to the 'middleBoot.ps1' script

$regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
$imgPath = "path\ToYour\Corporate\LockScreenImage.jpg"

reg.exe add $regPath /v LockScreenImagePath /t REG_SZ /d $imgPath /f
reg.exe add $regPath /v LockScreenImageUrl /t REG_SZ /d $imgPath /f
