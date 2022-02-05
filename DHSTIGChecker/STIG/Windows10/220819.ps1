<#
Rule Title: The network selection user interface (UI) must not be displayed on the logon screen.
Severity: medium
Vuln ID: V-220819
STIG ID: WN10-CC-000120

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