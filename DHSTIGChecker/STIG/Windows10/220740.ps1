# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220740
Rule ID:    SV-220740r569187_rule
STIG ID:    WN10-AC-000010
Legacy:     V-63409; SV-77899
Rule Title: The number of allowed bad logon attempts must be configured to 3 or less.
Discussion:
The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "LockoutBadCount"

if (($Result -ge 1) -and ($Result -le 3)) {
    $true
}
else {
    $false
}