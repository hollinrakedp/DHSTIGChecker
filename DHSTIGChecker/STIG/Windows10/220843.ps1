# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220843
Rule ID:    SV-220843r569187_rule
STIG ID:    WN10-CC-000245
Legacy:     V-63709; SV-78199
Rule Title: The password manager function in the Edge browser must be disabled.
Discussion:
Passwords save locally for re-use when browsing may be subject to compromise.  Disabling the Edge password manager will prevent this for the browser.


Check Content:
Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\

Value Name: FormSuggest Passwords

Type: REG_SZ
Value: no
#>

# No check for LTSB/LTSC
$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\"
    Name = "FormSuggest Passwords"
    ExpectedValue = "no"
}

Compare-RegKeyValue @Params