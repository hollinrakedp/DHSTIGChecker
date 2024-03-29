# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-220872
Rule ID:    SV-220872r569187_rule
STIG ID:    WN10-CC-000390
Legacy:     V-99563; SV-108667
Rule Title: Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications. 
Discussion:
Windows spotlight features may suggest apps and content from third-party software publishers in addition to Microsoft apps and content. 


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

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