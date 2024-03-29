# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224870
Rule ID:    SV-224870r569186_rule
STIG ID:    WN16-AC-000050
Legacy:     V-73317; SV-87969
Rule Title: Windows Server 2016 maximum password age must be configured to 60 days or less.
Discussion:
The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords. Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Maximum password age" is greater than "60" days, this is a finding.

If the value is set to "0" (never expires), this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "MaximumPasswordAge" is greater than "60" or equal to "0" in the file, this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "MaximumPasswordAge"

if (($Local:Result -gt 0) -and ($Local:Result -le 60)) {
    $true
}
else {
    $false
}