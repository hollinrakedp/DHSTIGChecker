# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224822
Rule ID:    SV-224822r569186_rule
STIG ID:    WN16-00-000050
Legacy:     V-73227; SV-87879
Rule Title: Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.
Discussion:
Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it. Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes. Members of the Backup Operators group must have separate logon accounts for performing backup duties.


Check Content:
If no accounts are members of the Backup Operators group, this is NA.

Verify users with accounts in the Backup Operators group have a separate user account for backup functions and for performing normal user tasks.

If users with accounts in the Backup Operators group do not have separate accounts for backup functions and standard user functions, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
