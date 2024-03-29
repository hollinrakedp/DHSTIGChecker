# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220795
Rule ID:    SV-220795r569187_rule
STIG ID:    WN10-CC-000020
Legacy:     V-63555; SV-78045
Rule Title: IPv6 source routing must be configured to highest protection.
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