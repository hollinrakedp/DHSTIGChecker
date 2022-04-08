<#
Rule Title: Windows Server 2019 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.
Severity: low
Vuln ID: V-205859
STIG ID: WN19-CC-000040

Discussion:
Configuring the system to disable IP source routing protects against spoofing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: DisableIPSourceRouting

Value Type: REG_DWORD
Value: 0x00000002 (2)

#>
return 'Not Reviewed'
