# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225027
Rule ID:    SV-225027r569186_rule
STIG ID:    WN16-SO-000040
Legacy:     V-73625; SV-88289
Rule Title: Windows Server 2016 built-in guest account must be renamed.
Discussion:
The built-in guest account is a well-known user account on all Windows systems and, as initially installed, does not require a password. This can allow access to system resources by unauthorized users. Renaming this account to an unidentified name improves the protection of this account and the system.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Rename guest account" is not set to a value other than "Guest", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "NewGuestName" is not something other than "Guest" in the file, this is a finding.
#>

$Account = "Guest"
$BuiltInAccount = Get-BuiltInAccount -Account $Account

if ($BuiltInAccount.Name -eq "$Account") {
    $false
}
else {
    $true
}