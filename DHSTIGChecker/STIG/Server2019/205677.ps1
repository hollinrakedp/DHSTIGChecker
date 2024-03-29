# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205677
Rule ID:    SV-205677r569188_rule
STIG ID:    WN19-00-000270
Legacy:     V-93381; SV-103467
Rule Title: Windows Server 2019 must have the roles and features required by the system documented.
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
