<#
Rule Title: The system must be configured to prevent IP source routing.
Severity: medium
Vuln ID: V-220796
STIG ID: WN10-CC-000025

Discussion:
Configuring the system to disable IP source routing protects against spoofing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: DisableIPSourceRouting

Value Type: REG_DWORD
Value: 2

#>

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
    Name = "DisableIPSourceRouting"
    ExpectedValue = 2
}

Compare-RegKeyValue @Params