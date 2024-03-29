# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-224819
Rule ID:    SV-224819r569186_rule
STIG ID:    WN16-00-000010
Legacy:     V-73217; SV-87869
Rule Title: Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.
Discussion:
Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.


Check Content:
Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account. 

If users with administrative privileges do not have separate accounts for administrative functions and standard user functions, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
