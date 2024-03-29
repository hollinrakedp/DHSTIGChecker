# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220819
Rule ID:    SV-220819r569187_rule
STIG ID:    WN10-CC-000120
Legacy:     V-63629; SV-78119
Rule Title: The network selection user interface (UI) must not be displayed on the logon screen.
Discussion:
Enabling interaction with the network selection UI allows users to change connections to available networks without signing into Windows.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

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