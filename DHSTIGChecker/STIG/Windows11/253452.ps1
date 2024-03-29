# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253452
Rule ID:    SV-253452r829440_rule
STIG ID:    WN11-SO-000140
Legacy:     
Rule Title: Anonymous SID/Name translation must not be allowed.
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