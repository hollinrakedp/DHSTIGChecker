# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225031
Rule ID:    SV-225031r852380_rule
STIG ID:    WN16-SO-000100
Legacy:     V-73637; SV-88301
Rule Title: The setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled.
Discussion:
Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked. If this policy is enabled, outgoing secure channel traffic will be signed.

Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: SignSecureChannel

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    Name          = "SignSecureChannel"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params