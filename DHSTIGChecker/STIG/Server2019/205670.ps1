# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205670
Rule ID:    SV-205670r569188_rule
STIG ID:    WN19-DC-000400
Legacy:     V-93005; SV-103093
Rule Title: Windows Server 2019 Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on locally" user right defines accounts that are prevented from logging on interactively.

The Guests group must be assigned this right to prevent unauthenticated access.


Check Content:
This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on locally" user right, this is a finding:

- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If the following SID(s) are not defined for the "SeDenyInteractiveLogonRight" user right, this is a finding:

S-1-5-32-546 (Guests)
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}