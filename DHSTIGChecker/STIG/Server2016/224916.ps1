<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   low
Vuln ID:    V-224916
Rule ID:    SV-224916r569186_rule
STIG ID:    WN16-CC-000040
Legacy:     V-73499; SV-88151
Rule Title: Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.
Discussion:
Configuring the system to disable IPv6 source routing protects against spoofing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name: DisableIPSourceRouting

Type: REG_DWORD
Value: 0x00000002 (2)
#>

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
    Name = "DisableIpSourceRouting"
    ExpectedValue = 2
}

Compare-RegKeyValue @Params