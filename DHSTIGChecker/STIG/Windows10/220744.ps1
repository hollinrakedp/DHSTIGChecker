<#
Rule Title: The minimum password age must be configured to at least 1 day.
Severity: medium
Vuln ID: V-220744
STIG ID: WN10-AC-000030

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