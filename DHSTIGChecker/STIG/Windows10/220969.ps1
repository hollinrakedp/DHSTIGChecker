<#
Rule Title: The Deny log on as a batch job user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
Severity: medium
Vuln ID: V-220969
STIG ID: WN10-UR-000075

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on as a batch job" right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.


Check Content:
This requirement is applicable to domain-joined systems, for standalone systems this is NA.

Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following groups or accounts are not defined for the "Deny log on as a batch job" right, this is a finding:

Domain Systems Only:
Enterprise Admin Group
Domain Admin Group

#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "This check does not apply: Reason - Not Domain-Joined"
    return "Not Applicable"
}

#Incomplete
return "Not Reviewed"