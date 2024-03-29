# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253425
Rule ID:    SV-253425r829359_rule
STIG ID:    WN11-CC-000390
Legacy:     
Rule Title: Windows 11 must be configured to prevent users from receiving suggestions for third-party or additional applications.
Discussion:
Windows spotlight features may suggest apps and content from third-party software publishers in addition to Microsoft apps and content.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CloudContent\

Value Name: DisableThirdPartySuggestions

Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\"
    Name          = "DisableThirdPartySuggestions"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params