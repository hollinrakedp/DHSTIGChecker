# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224873
Rule ID:    SV-224873r569186_rule
STIG ID:    WN16-AC-000080
Legacy:     V-73323; SV-87975
Rule Title: Windows Server 2016 must have the built-in Windows password complexity policy enabled.
Discussion:
The use of complex passwords increases their strength against attack. The built-in Windows password complexity policy requires passwords to contain at least three of the four types of characters (numbers, upper- and lower-case letters, and special characters) and prevents the inclusion of user names or parts of user names.

Satisfies: SRG-OS-000069-GPOS-00037, SRG-OS-000070-GPOS-00038, SRG-OS-000071-GPOS-00039, SRG-OS-000266-GPOS-00101


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Password must meet complexity requirements" is not set to "Enabled", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "PasswordComplexity" equals "0" in the file, this is a finding.

Note: If an external password filter is in use that enforces all four character types and requires this setting to be set to "Disabled", this would not be considered a finding. If this setting does not affect the use of an external password filter, it must be enabled for fallback purposes.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "PasswordComplexity"

if ($Local:Result -eq 1) {
    $true
}
else {
    $false
}