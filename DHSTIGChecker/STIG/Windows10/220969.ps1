# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220969
Rule ID:    SV-220969r857200_rule
STIG ID:    WN10-UR-000075
Legacy:     V-63873; SV-78363
Rule Title: The "Deny log on as a batch job" user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a batch job" right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks that could lead to the compromise of an entire domain.


Check Content:
This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following groups or accounts are not defined for the "Deny log on as a batch job" right, this is a finding.

Domain Systems Only:
Enterprise Admin Group
Domain Admin Group
#>

# PARTIAL
if (!($Script:IsDomainJoined)) {
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

return "Not Reviewed"