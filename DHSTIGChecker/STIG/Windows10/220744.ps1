# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220744
Rule ID:    SV-220744r569187_rule
STIG ID:    WN10-AC-000030
Legacy:     V-63421; SV-77911
Rule Title: The minimum password age must be configured to at least 1 day.
Discussion:
Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database.  This enables users to effectively negate the purpose of mandating periodic password changes.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Minimum password age" is less than "1" day, this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "MinimumPasswordAge"

if ($Local:Result -gt 0) {
    $true
}
else {
    $false
}