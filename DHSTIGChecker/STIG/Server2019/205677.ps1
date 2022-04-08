<#
Rule Title: Windows Server 2019 must have the roles and features required by the system documented.
Severity: medium
Vuln ID: V-205677
STIG ID: WN19-00-000270

Discussion:
Unnecessary roles and features increase the attack surface of a system. Limiting roles and features of a system to only those necessary reduces this potential. The standard installation option (previously called Server Core) further reduces this when selected at installation.


Check Content:
Required roles and features will vary based on the function of the individual system.

Roles and features specifically required to be disabled per the STIG are identified in separate requirements.

If the organization has not documented the roles and features required for the system(s), this is a finding.

The PowerShell command "Get-WindowsFeature" will list all roles and features with an "Install State".

#>
return 'Not Reviewed'
