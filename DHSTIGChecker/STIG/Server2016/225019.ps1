<#
Rule Title: The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and from unauthenticated access on all systems.
Severity: medium
Vuln ID: V-225019
STIG ID: WN16-MS-000410

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on through Remote Desktop Services" user right defines the accounts that are prevented from logging on using Remote Desktop Services.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.


Check Content:
This applies to member servers and standalone systems. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on through Remote Desktop Services" user right, this is a finding.

Domain Systems Only:
- Enterprise Admins group
- Domain Admins group
- Local account (see Note below)

All Systems:
- Guests group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyRemoteInteractiveLogonRight" user right, this is a finding.

Domain Systems Only:
S-1-5-root domain-519 (Enterprise Admins)
S-1-5-domain-512 (Domain Admins)
S-1-5-113 ("Local account")

All Systems:
S-1-5-32-546 (Guests)

Note: "Local account" is referring to the Windows built-in security group.

#>
return 'Not Reviewed'
