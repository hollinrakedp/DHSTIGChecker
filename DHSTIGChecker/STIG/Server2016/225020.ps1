# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225020
Rule ID:    SV-225020r877392_rule
STIG ID:    WN16-MS-000420
Legacy:     V-73779; SV-88443
Rule Title: The "Enable computer and user accounts to be trusted for delegation" user right must not be assigned to any groups or accounts on member servers.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed. This could allow unauthorized users to impersonate other users.


Check Content:
This applies to member servers and standalone or nondomain-joined systems. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs are granted the "SeEnableDelegationPrivilege" user right, this is a finding.
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Applicable"
}
else {
    "Not Reviewed"
}