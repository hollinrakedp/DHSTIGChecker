# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205674
Rule ID:    SV-205674r891848_rule
STIG ID:    WN19-MS-000100
Legacy:     V-93013; SV-103101
Rule Title: Windows Server 2019 "Deny log on as a service" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied logon as a service.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a denial of service.


Check Content:
This applies to member servers only. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a service" user right on domain-joined systems, this is a finding:

- Enterprise Admins Group
- Domain Admins Group

If any accounts or groups are defined for the "Deny log on as a service" user right on nondomain-joined systems, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyServiceLogonRight" user right on domain-joined systems, this is a finding:

S-1-5-root domain-519 (Enterprise Admins)
S-1-5-domain-512 (Domain Admins)

If any SIDs are defined for the user right, this is a finding.
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}