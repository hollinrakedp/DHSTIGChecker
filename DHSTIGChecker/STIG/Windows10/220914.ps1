<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   medium
Vuln ID:    V-220914
Rule ID:    SV-220914r852008_rule
STIG ID:    WN10-SO-000035
Legacy:     V-63639; SV-78129
Rule Title: Outgoing secure channel traffic must be encrypted or signed.
Discussion:
Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RequireSignOrSeal

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    Name          = "RequireSignOrSeal"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params