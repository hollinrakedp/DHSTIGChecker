<#
Rule Title: Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.
Severity: medium
Vuln ID: V-225057
STIG ID: WN16-SO-000410

Discussion:
Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\

Value Name: NTLMMinServerSec

Value Type: REG_DWORD
Value: 0x20080000 (537395200)

#>
return 'Not Reviewed'
