# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205690
Rule ID:    SV-205690r569188_rule
STIG ID:    WN19-CC-000170
Legacy:     V-93407; SV-103493
Rule Title: Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen.
Discussion:
Enabling interaction with the network selection UI allows users to change connections to available networks without signing in to Windows.


Check Content:
Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: DontDisplayNetworkSelectionUI

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name = "DontDisplayNetworkSelectionUI"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params