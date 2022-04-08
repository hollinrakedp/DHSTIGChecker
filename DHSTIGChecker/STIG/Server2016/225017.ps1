<#
Rule Title: The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems. No other groups or accounts must be assigned this right.
Severity: medium
Vuln ID: V-225017
STIG ID: WN16-MS-000390

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied logon as a service.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS.


Check Content:
This applies to member servers and standalone systems. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a service" user right on domain-joined systems, this is a finding.

- Enterprise Admins Group
- Domain Admins Group

If any accounts or groups are defined for the "Deny log on as a service" user right on non-domain-joined systems, this is a finding.
For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyServiceLogonRight" user right on domain-joined systems, this is a finding.

S-1-5-root domain-519 (Enterprise Admins)
S-1-5-domain-512 (Domain Admins)

If any SIDs are defined for the user right on non-domain-joined systems, this is a finding.

#>
return 'Not Reviewed'
