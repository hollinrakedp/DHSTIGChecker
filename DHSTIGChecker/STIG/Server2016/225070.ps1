# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225070
Rule ID:    SV-225070r877392_rule
STIG ID:    WN16-UR-000010
Legacy:     V-73729; SV-88393
Rule Title: The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access Credential Manager as a trusted caller" user right may be able to retrieve the credentials of other accounts from Credential Manager.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Access Credential Manager as a trusted caller" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs are granted the "SeTrustedCredManAccessPrivilege" user right, this is a finding.
#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeTrustedCredManAccessPrivilege -split ',').trimstart('*')

if ($null -eq $GrantedPrivilege) {
    $true
}
else {
    $false
}