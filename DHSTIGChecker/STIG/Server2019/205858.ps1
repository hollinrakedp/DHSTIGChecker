<#
Rule Title: Windows Server 2019 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.
Severity: low
Vuln ID: V-205858
STIG ID: WN19-CC-000030

Discussion:
Configuring the system to disable IPv6 source routing protects against spoofing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name: DisableIPSourceRouting

Type: REG_DWORD
Value: 0x00000002 (2)

#>
return 'Not Reviewed'
