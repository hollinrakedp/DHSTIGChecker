# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-205663
Rule ID:    SV-205663r569188_rule
STIG ID:    WN19-00-000130
Legacy:     V-92991; SV-103079
Rule Title: Windows Server 2019 local volumes must use a format that supports NTFS attributes.
Discussion:
The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system. To support this, volumes must be formatted using a file system that supports NTFS attributes.


Check Content:
Open "Computer Management".

Select "Disk Management" under "Storage".

For each local volume, if the file system does not indicate "NTFS", this is a finding.

"ReFS" (resilient file system) is also acceptable and would not be a finding.

This does not apply to system partitions such the Recovery and EFI System Partition.
#>

$FixedDrives = Get-Volume | Where-Object {($_.DriveType -eq 'Fixed') -and ($null -ne $_.DriveLetter)}

$Local:Results = @()
$Local:Results += $FixedDrives | Where-Object {$_.FileSystemType -eq 'NTFS'}
$Local:Results.Count -eq $FixedDrives.Count