# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220743
Rule ID:    SV-220743r569187_rule
STIG ID:    WN10-AC-000025
Legacy:     V-63419; SV-77909
Rule Title: The maximum password age must be configured to 60 days or less.
Discussion:
The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.   Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Maximum password age" is greater than "60" days, this is a finding.  If the value is set to "0" (never expires), this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "MaximumPasswordAge"

if (($Local:Result -gt 0) -and ($Local:Result -le 60)) {
    $true
}
else {
    $false
}