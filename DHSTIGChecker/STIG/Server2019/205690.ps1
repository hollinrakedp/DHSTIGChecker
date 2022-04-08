<#
Rule Title: Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen.
Severity: medium
Vuln ID: V-205690
STIG ID: WN19-CC-000170

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
return 'Not Reviewed'
