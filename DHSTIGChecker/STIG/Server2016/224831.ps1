# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-224831
Rule ID:    SV-224831r569186_rule
STIG ID:    WN16-00-000150
Legacy:     V-73247; SV-87899
Rule Title: Local volumes must use a format that supports NTFS attributes.
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