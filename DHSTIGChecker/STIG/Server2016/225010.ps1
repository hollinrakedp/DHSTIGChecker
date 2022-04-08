<#
Rule Title: Unauthenticated Remote Procedure Call (RPC) clients must be restricted from connecting to the RPC server.
Severity: medium
Vuln ID: V-225010
STIG ID: WN16-MS-000040

Discussion:
Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.


Check Content:
This applies to member servers and standalone systems, It is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows NT\Rpc\

Value Name:  RestrictRemoteClients

Type:  REG_DWORD
Value:  0x00000001 (1)

#>
return 'Not Reviewed'
