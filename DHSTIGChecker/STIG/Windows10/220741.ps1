<#
Rule Title: The period of time before the bad logon counter is reset must be configured to 15 minutes.
Severity: medium
Vuln ID: V-220741
STIG ID: WN10-AC-000015

Discussion:
The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to 0.  The smaller this value is, the less effective the account lockout feature will be in protecting the local system.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.

#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "ResetLockoutCount"

if ($Local:Result -ge 15) {
    $true
}
else {
    $false
}