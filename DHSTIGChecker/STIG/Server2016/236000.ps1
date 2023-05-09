<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   medium
Vuln ID:    V-236000
Rule ID:    SV-236000r641817_rule
STIG ID:    WN16-CC-000421
Legacy:     V-102623; SV-111573
Rule Title: The Windows Explorer Preview pane must be disabled for Windows Server 2016.
Discussion:
A known vulnerability in Windows could allow the execution of malicious code by either opening a compromised document or viewing it in the Windows Preview pane.

Organizations must disable the Windows Preview pane and Windows Detail pane.


Check Content:
If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer

Value Name: NoPreviewPane

Value Type: REG_DWORD

Value: 1

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer

Value Name: NoReadingPane

Value Type: REG_DWORD

Value: 1

#>

$Local:Results = @()
$Local:Names = "NoPreviewPane", "NoReadingPane"

foreach ($_ in $Local:Names) {
    $Params = @{
        Path          = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
        Name          = "$_"
        ExpectedValue = 1
    }
        
    $Local:Results += Compare-RegKeyValue @Params
}

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}