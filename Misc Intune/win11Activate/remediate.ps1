# Define your MAK key
$MAKKey = "ABCD-1234-EFGH-5678-IJKL"  # Replace with your actual MAK key

# Set the MAK key
Write-Output "Installing MAK key... $MAKKey"
slmgr.vbs /ipk $MAKKey

# Activate Windows
Write-Output "Activating Windows..."
slmgr.vbs /ato

# Display the activation status
Write-Output "Checking activation status..."
slmgr.vbs /dlv

Write-Output "Windows activation process completed."