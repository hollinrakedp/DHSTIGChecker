# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225077
Rule ID:    SV-225077r877392_rule
STIG ID:    WN16-UR-000110
Legacy:     V-73751; SV-88415
Rule Title: The Create permanent shared objects user right must not be assigned to any groups or accounts.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create permanent shared objects" user right could expose sensitive data by creating shared objects.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Create permanent shared objects" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs are granted the "SeCreatePermanentPrivilege" user right, this is a finding.
#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeCreatePermanentPrivilege -split ',').trimstart('*')

if ($null -eq $GrantedPrivilege) {
    $true
}
else {
    $false
}