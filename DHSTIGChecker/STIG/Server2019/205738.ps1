<#
Rule Title: Windows Server 2019 must only allow administrators responsible for the domain controller to have Administrator rights on the system.
Severity: high
Vuln ID: V-205738
STIG ID: WN19-DC-000010

Discussion:
An account that does not have Administrator duties must not have Administrator rights. Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems using only accounts with the minimum level of authority necessary. 

Standard user accounts must not be members of the built-in Administrators group.


Check Content:
This applies to domain controllers. A separate version applies to other systems.

Review the Administrators group. Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

Standard user accounts must not be members of the local administrator group.

If prohibited accounts are members of the local administrators group, this is a finding.

If the built-in Administrator account or other required administrative accounts are found on the system, this is not a finding.

#>
return 'Not Reviewed'
