<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   medium
Vuln ID:    V-205846
Rule ID:    SV-205846r569188_rule
STIG ID:    WN19-00-000040
Legacy:     V-93207; SV-103295
Rule Title: Windows Server 2019 members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.
Discussion:
Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it. Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes. Members of the Backup Operators group must have separate logon accounts for performing backup duties.


Check Content:
If no accounts are members of the Backup Operators group, this is NA.

Verify users with accounts in the Backup Operators group have a separate user account for backup functions and for performing normal user tasks.

If users with accounts in the Backup Operators group do not have separate accounts for backup functions and standard user functions, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
