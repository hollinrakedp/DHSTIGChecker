# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253300
Rule ID:    SV-253300r828984_rule
STIG ID:    WN11-AC-000020
Legacy:     
Rule Title: The password history must be configured to 24 passwords remembered.
Discussion:
A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change a password to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes. The default value is 24 for Windows domain systems. DoD has decided this is the appropriate value for all Windows systems.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Enforce password history" is less than "24" passwords remembered, this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "PasswordHistorySize"

if ($Local:Result -ge 24) {
    $true
}
else {
    $false
}