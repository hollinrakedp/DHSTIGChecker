# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220747
Rule ID:    SV-220747r877397_rule
STIG ID:    WN10-AC-000045
Legacy:     V-63429; SV-77919
Rule Title: Reversible password encryption must be disabled.
Discussion:
Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords. For this reason, this policy must never be enabled.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Store password using reversible encryption" is not set to "Disabled", this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "ClearTextPassword"

if ($Local:Result -eq 0) {
    $true
}
else {
    $false
}