# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-205859
Rule ID:    SV-205859r569188_rule
STIG ID:    WN19-CC-000040
Legacy:     V-93235; SV-103323
Rule Title: Windows Server 2019 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.
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

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
    Name          = "DisableIPSourceRouting"
    ExpectedValue = 2
}

Compare-RegKeyValue @Params