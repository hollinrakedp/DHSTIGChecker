<#
Rule Title: The built-in Microsoft password complexity filter must be enabled.
Severity: medium
Vuln ID: V-220746
STIG ID: WN10-AC-000040

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