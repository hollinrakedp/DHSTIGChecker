# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224999
Rule ID:    SV-224999r569186_rule
STIG ID:    WN16-DC-000360
Legacy:     V-73741; SV-88405
Rule Title: The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Allow log on through Remote Desktop Services" user right can access a system through Remote Desktop.


Check Content:
This applies to domain controllers, it is NA for other systems.

Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeRemoteInteractiveLogonRight" user right, this is a finding.

S-1-5-32-544 (Administrators)
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}