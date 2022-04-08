<#
Rule Title: Windows Server 2019 local volumes must use a format that supports NTFS attributes.
Severity: high
Vuln ID: V-205663
STIG ID: WN19-00-000130

Discussion:
The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system. To support this, volumes must be formatted using a file system that supports NTFS attributes.


Check Content:
Open "Computer Management".

Select "Disk Management" under "Storage".

For each local volume, if the file system does not indicate "NTFS", this is a finding.

"ReFS" (resilient file system) is also acceptable and would not be a finding.

This does not apply to system partitions such the Recovery and EFI System Partition.

#>
return 'Not Reviewed'
