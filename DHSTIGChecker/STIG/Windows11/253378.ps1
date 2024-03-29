# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253378
Rule ID:    SV-253378r829218_rule
STIG ID:    WN11-CC-000120
Legacy:     
Rule Title: The network selection user interface (UI) must not be displayed on the logon screen.
Discussion:
Enabling interaction with the network selection UI allows users to change connections to available networks without signing into Windows.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: DontDisplayNetworkSelectionUI

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name = "DontDisplayNetworkSelectionUI"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params