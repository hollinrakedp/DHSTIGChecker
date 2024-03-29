# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253439
Rule ID:    SV-253439r829401_rule
STIG ID:    WN11-SO-000040
Legacy:     
Rule Title: Outgoing secure channel traffic must be encrypted.
Discussion:
Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: SealSecureChannel

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    Name          = "SealSecureChannel"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params