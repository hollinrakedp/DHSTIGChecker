<#
Rule Title: The built-in administrator account must be renamed.
Severity: medium
Vuln ID: V-220911
STIG ID: WN10-SO-000020

Discussion:
The built-in administrator account is a well-known account subject to attack.  Renaming this account to an unidentified name improves the protection of this account and the system.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Rename administrator account" is set to "Administrator", this is a finding.

#>

$Account = "Administrator"
$BuiltInAccount = Get-BuiltInAccount -Account $Account

if ($BuiltInAccount.Name -eq "$Account") {
    $false
}
else {
    $true
}