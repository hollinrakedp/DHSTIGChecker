# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-224917
Rule ID:    SV-224917r569186_rule
STIG ID:    WN16-CC-000050
Legacy:     V-73501; SV-88153
Rule Title: Source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.
Discussion:
Configuring the system to disable IP source routing protects against spoofing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: DisableIPSourceRouting

Value Type: REG_DWORD
Value: 0x00000002 (2)
#>

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
    Name = "DisableIPSourceRouting"
    ExpectedValue = 2
}

Compare-RegKeyValue @Params