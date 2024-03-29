# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253432
Rule ID:    SV-253432r829380_rule
STIG ID:    WN11-SO-000005
Legacy:     
Rule Title: The built-in administrator account must be disabled.
Discussion:
The built-in administrator account is a well-known account subject to attack. It also provides no accountability to individual administrators on a system. It must be disabled to prevent its use.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Administrator account status" is not set to "Disabled", this is a finding.
#>

$Account = "Administrator"
$BuiltInAccount = Get-BuiltInAccount -Account $Account

if ($BuiltInAccount.Enabled) {
    $false
}
else {
    $true
}