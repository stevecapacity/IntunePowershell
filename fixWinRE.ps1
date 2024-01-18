# Get the disk that contains the Win RE partition
$disk = Get-Disk | Where-Object { $_.PartitionStyle -eq 'GPT' } | Sort-Object -Property Number | Select-Object -Last 1

# Get the Win RE partition
$partition = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Type -eq 'Recovery' }

# Get all partitions on the disk, sorted by partition number
$allPartitions = Get-Partition -DiskNumber $disk.Number | Sort-Object -Property PartitionNumber

# Check if the Win RE partition is the last partition on the disk
if ($partition.PartitionNumber -eq $allPartitions[-1].PartitionNumber) {
    # Calculate the new size in bytes
    $newSize = 1GB

    # Calculate the size to add in bytes
    $sizeToAdd = $newSize - $partition.Size

    # Resize the partition
    Resize-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -Size ($partition.Size + $sizeToAdd)
} else {
    Write-Output "The Win RE partition is not the last partition on the disk."
}
