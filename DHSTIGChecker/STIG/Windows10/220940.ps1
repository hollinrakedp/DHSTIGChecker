<#
Rule Title: The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.
Severity: medium
Vuln ID: V-220940
STIG ID: WN10-SO-000215

Discussion:
Microsoft has implemented a variety of security support providers for use with RPC sessions.  All of the options must be enabled to ensure the maximum security level.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

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