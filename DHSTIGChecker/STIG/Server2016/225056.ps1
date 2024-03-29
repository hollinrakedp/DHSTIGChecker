# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225056
Rule ID:    SV-225056r569186_rule
STIG ID:    WN16-SO-000400
Legacy:     V-73695; SV-88359
Rule Title: Session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption.
Discussion:
Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\

Value Name: NTLMMinClientSec

Value Type: REG_DWORD
Value: 0x20080000 (537395200)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
    Name          = "NTLMMinClientSec"
    ExpectedValue = 537395200
}

Compare-RegKeyValue @Params