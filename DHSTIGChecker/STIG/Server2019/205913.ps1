# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-205913
Rule ID:    SV-205913r569188_rule
STIG ID:    WN19-SO-000210
Legacy:     V-93289; SV-103377
Rule Title: Windows Server 2019 must not allow anonymous SID/Name translation.
Discussion:
Allowing anonymous SID/Name translation can provide sensitive information for accessing a system. Only authorized users must be able to perform such translations.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.
#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "LSAAnonymousNameLookup"

if ($Local:Result -eq 0) {
    $true
}
else {
    $false
}