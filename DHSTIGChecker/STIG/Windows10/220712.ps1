<#
Rule Title: Only accounts responsible for the administration of a system must have Administrator rights on the system.
Severity: high
Vuln ID: V-220712
STIG ID: WN10-00-000070

Discussion:
An account that does not have Administrator duties must not have Administrator rights.  Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems only using accounts with the minimum level of authority necessary.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group (see V-36434 in the Active Directory Domain STIG).  Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.

Standard user accounts must not be members of the local administrators group.


Check Content:
Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Groups.
Review the members of the Administrators group.
Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group.

Standard user accounts must not be members of the local administrator group.

If prohibited accounts are members of the local administrators group, this is a finding.

The built-in Administrator account or other required administrative accounts would not be a finding.

#>

#Incomplete
return "Not Reviewed"