# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253265
Rule ID:    SV-253265r828879_rule
STIG ID:    WN11-00-000050
Legacy:     
Rule Title: Local volumes must be formatted using NTFS.
Discussion:
The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system. To support this, volumes must be formatted using the NTFS file system.


Check Content:
Run "Computer Management".
Navigate to Storage >> Disk Management.

If the "File System" column does not indicate "NTFS" for each volume assigned a drive letter, this is a finding.

This does not apply to system partitions such the Recovery and EFI System Partition.
#>

$FixedDrives = Get-Volume | Where-Object {($_.DriveType -eq 'Fixed') -and ($null -ne $_.DriveLetter)}

$Local:Results = @()
$Local:Results += $FixedDrives | Where-Object {$_.FileSystemType -eq 'NTFS'}
$Local:Results.Count -eq $FixedDrives.Count