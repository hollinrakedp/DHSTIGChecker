# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220824
Rule ID:    SV-220824r877039_rule
STIG ID:    WN10-CC-000165
Legacy:     V-63657; SV-78147
Rule Title: Unauthenticated RPC clients must be restricted from connecting to the RPC server.
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