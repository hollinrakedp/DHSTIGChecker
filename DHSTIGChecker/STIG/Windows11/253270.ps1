# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253270
Rule ID:    SV-253270r828894_rule
STIG ID:    WN11-00-000075
Legacy:     
Rule Title: Only accounts responsible for the backup operations must be members of the Backup Operators group.
Discussion:
Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it. Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes. Members of the Backup Operators group must have separate logon accounts for performing backup duties.


Check Content:
Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Groups.
Review the members of the Backup Operators group.

If the group contains no accounts, this is not a finding.

If the group contains any accounts, the accounts must be specifically for backup functions.

If the group contains any standard user accounts used for performing normal user tasks, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
