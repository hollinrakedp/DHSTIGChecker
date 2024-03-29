# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225002
Rule ID:    SV-225002r569186_rule
STIG ID:    WN16-DC-000390
Legacy:     V-73765; SV-88429
Rule Title: The Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied logon as a service.

Incorrect configurations could prevent services from starting and result in a denial of service.


Check Content:
This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are defined for the "Deny log on as a service" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs are granted the "SeDenyServiceLogonRight" user right, this is a finding.
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}