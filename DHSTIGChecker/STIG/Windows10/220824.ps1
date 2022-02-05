<#
Rule Title: Unauthenticated RPC clients must be restricted from connecting to the RPC server.
Severity: medium
Vuln ID: V-220824
STIG ID: WN10-CC-000165

Discussion:
Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Rpc\

Value Name: RestrictRemoteClients

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
    Name = "RestrictRemoteClients"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params