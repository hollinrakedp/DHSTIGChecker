<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   high
Vuln ID:    V-224874
Rule ID:    SV-224874r569186_rule
STIG ID:    WN16-AC-000090
Legacy:     V-73325; SV-87977
Rule Title: Windows Server 2016 reversible password encryption must be disabled.
Discussion:
Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords, which are easily compromised. For this reason, this policy must never be enabled.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Store passwords using reversible encryption" is not set to "Disabled", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "ClearTextPassword" equals "1" in the file, this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "ClearTextPassword"

if ($Local:Result -eq 0) {
    $true
}
else {
    $false
}