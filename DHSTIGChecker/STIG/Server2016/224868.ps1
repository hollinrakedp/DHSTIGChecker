# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224868
Rule ID:    SV-224868r852302_rule
STIG ID:    WN16-AC-000030
Legacy:     V-73313; SV-87965
Rule Title: Windows Server 2016 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.
Discussion:
The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to "0". The smaller this value is, the less effective the account lockout feature will be in protecting the local system.

Satisfies: SRG-OS-000021-GPOS-00005, SRG-OS-000329-GPOS-00128


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "ResetLockoutCount" is less than "15" in the file, this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "ResetLockoutCount"

if ($Local:Result -ge 15) {
    $true
}
else {
    $false
}