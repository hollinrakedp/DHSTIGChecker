<#
Rule Title: Only administrators responsible for the member server or standalone system must have Administrator rights on the system.
Severity: high
Vuln ID: V-225007
STIG ID: WN16-MS-000010

Discussion:
An account that does not have Administrator duties must not have Administrator rights. Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems using only accounts with the minimum level of authority necessary.

For domain-joined member servers, the Domain Admins group must be replaced by a domain member server administrator group (see V-36433 in the Active Directory Domain STIG). Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.

Standard user accounts must not be members of the built-in Administrators group.


Check Content:
This applies to member servers and standalone systems. A separate version applies to domain controllers.

Open "Computer Management".

Navigate to "Groups" under "Local Users and Groups".

Review the local "Administrators" group.

Only administrator groups or accounts responsible for administration of the system may be members of the group.

For domain-joined member servers, the Domain Admins group must be replaced by a domain member server administrator group.

Standard user accounts must not be members of the local Administrator group.

If accounts that do not have responsibility for administration of the system are members of the local Administrators group, this is a finding.

If the built-in Administrator account or other required administrative accounts are found on the system, this is not a finding.

#>
return 'Not Reviewed'
