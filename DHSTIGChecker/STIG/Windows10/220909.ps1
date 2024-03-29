# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220909
Rule ID:    SV-220909r569187_rule
STIG ID:    WN10-SO-000010
Legacy:     V-63611; SV-78101
Rule Title: The built-in guest account must be disabled.
Discussion:
A system faces an increased vulnerability threat if the built-in guest account is not disabled.  This account is a known account that exists on all Windows systems and cannot be deleted.  This account is initialized during the installation of the operating system with no password assigned.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.
#>

$Account = "Guest"
$BuiltInAccount = Get-BuiltInAccount -Account $Account

if ($BuiltInAccount.Enabled) {
    $false
}
else {
    $true
}