# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253449
Rule ID:    SV-253449r829431_rule
STIG ID:    WN11-SO-000100
Legacy:     
Rule Title: The Windows SMB client must be configured to always perform SMB packet signing.
Discussion:
The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name: RequireSecuritySignature

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
    Name          = "RequireSecuritySignature"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params