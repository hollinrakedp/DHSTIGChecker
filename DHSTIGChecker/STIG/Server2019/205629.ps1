# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205629
Rule ID:    SV-205629r569188_rule
STIG ID:    WN19-AC-000020
Legacy:     V-93141; SV-103229
Rule Title: Windows Server 2019 must have the number of allowed bad logon attempts configured to three or less.
Discussion:
The account lockout feature, when enabled, prevents brute-force password attacks on the system. The higher this value is, the less effective the account lockout feature will be in protecting the local system. The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack while allowing for honest errors made during normal user logon.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "LockoutBadCount" equals "0" or is greater than "3" in the file, this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "LockoutBadCount"

if (($Result -ge 1) -and ($Result -le 3)) {
    $true
}
else {
    $false
}