# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-205819
Rule ID:    SV-205819r852521_rule
STIG ID:    WN19-CC-000060
Legacy:     V-93541; SV-103627
Rule Title: Windows Server 2019 must be configured to ignore NetBIOS name release requests except from WINS servers.
Discussion:
Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the server's WINS resolution capability.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\Netbt\Parameters\

Value Name:  NoNameReleaseOnDemand

Value Type:  REG_DWORD
Value:  0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\"
    Name = "NoNameReleaseOnDemand"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params