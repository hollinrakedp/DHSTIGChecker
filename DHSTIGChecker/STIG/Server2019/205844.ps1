# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-205844
Rule ID:    SV-205844r569188_rule
STIG ID:    WN19-00-000010
Legacy:     V-93369; SV-103457
Rule Title: Windows Server 2019 users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.
Discussion:
Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.


Check Content:
Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account. 

If users with administrative privileges do not have separate accounts for administrative functions and standard user functions, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
