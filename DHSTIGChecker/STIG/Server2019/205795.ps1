# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205795
Rule ID:    SV-205795r852496_rule
STIG ID:    WN19-AC-000010
Legacy:     V-93145; SV-103233
Rule Title: Windows Server 2019 account lockout duration must be configured to 15 minutes or greater.
Discussion:
The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout duration" is less than "15" minutes (excluding "0"), this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "LockoutDuration" is less than "15" (excluding "0") in the file, this is a finding.

Configuring this to "0", requiring an administrator to unlock the account, is more restrictive and is not a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "LockoutDuration"

if (($Local:Result -eq 0) -or ($Local:Result -ge 15)) {
    $true
}
else {
    $false
}