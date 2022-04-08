<#
Rule Title: The Deny log on as a service user right on Windows 10 domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
Severity: medium
Vuln ID: V-220970
STIG ID: WN10-UR-000080

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on as a service" right defines accounts that are denied log on as a service.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS.


Check Content:
This requirement is applicable to domain-joined systems, for standalone systems this is NA.

Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following groups or accounts are not defined for the "Deny log on as a service" right , this is a finding:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "This check does not apply: Reason - Not Domain-Joined"
    return "Not Applicable"
}

#Incomplete
return "Not Reviewed"