# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220746
Rule ID:    SV-220746r569187_rule
STIG ID:    WN10-AC-000040
Legacy:     V-63427; SV-77917
Rule Title: The built-in Microsoft password complexity filter must be enabled.
Discussion:
The use of complex passwords increases their strength against guessing and brute-force attacks.  This setting configures the system to verify that newly created passwords conform to the Windows password complexity policy.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Password must meet complexity requirements" is not set to "Enabled", this is a finding.

If the site is using a password filter that requires this setting be set to "Disabled" for the filter to be used, this would not be considered a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "PasswordComplexity"

if ($Local:Result -eq 1) {
    $true
}
else {
    $false
}