# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224845
Rule ID:    SV-224845r569186_rule
STIG ID:    WN16-00-000300
Legacy:     V-73277; SV-87929
Rule Title: The roles and features required by the system must be documented.
Discussion:
Unnecessary roles and features increase the attack surface of a system. Limiting roles and features of a system to only those necessary reduces this potential. The standard installation option (previously called Server Core) further reduces this when selected at installation.


Check Content:
Required roles and features will vary based on the function of the individual system.

Roles and features specifically required to be disabled per the STIG are identified in separate requirements.

If the organization has not documented the roles and features required for the system(s), this is a finding.

The PowerShell command "Get-WindowsFeature" will list all roles and features with an "Install State".
#>

# INCOMPLETE
return 'Not Reviewed'
