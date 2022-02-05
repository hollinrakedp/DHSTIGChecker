<#
Rule Title: IPv6 source routing must be configured to highest protection.
Severity: medium
Vuln ID: V-220795
STIG ID: WN10-CC-000020

Discussion:
Configuring the system to disable IPv6 source routing protects against spoofing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name: DisableIpSourceRouting

Value Type: REG_DWORD
Value: 2

#>

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
    Name = "DisableIpSourceRouting"
    ExpectedValue = 2
}

Compare-RegKeyValue @Params