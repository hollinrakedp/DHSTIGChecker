# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220739
Rule ID:    SV-220739r851968_rule
STIG ID:    WN10-AC-000005
Legacy:     V-63405; SV-77895
Rule Title: Windows 10 account lockout duration must be configured to 15 minutes or greater.
Discussion:
The account lockout feature, when enabled, prevents brute-force password attacks on the system.   This parameter specifies the amount of time that an account will remain locked after the specified number of failed logon attempts.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout duration" is less than "15" minutes (excluding "0"), this is a finding.

Configuring this to "0", requiring an administrator to unlock the account, is more restrictive and is not a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "LockoutDuration"

if (($Local:Result -eq 0) -or ($Local:Result -ge 15)) {
    $true
}
else {
    $false
}