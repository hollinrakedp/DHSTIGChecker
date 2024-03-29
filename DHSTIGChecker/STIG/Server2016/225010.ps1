# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225010
Rule ID:    SV-225010r877039_rule
STIG ID:    WN16-MS-000040
Legacy:     V-73541; SV-88203
Rule Title: Unauthenticated Remote Procedure Call (RPC) clients must be restricted from connecting to the RPC server.
Discussion:
Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.


Check Content:
This applies to member servers and standalone or nondomain-joined systems. It is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows NT\Rpc\

Value Name:  RestrictRemoteClients

Type:  REG_DWORD
Value:  0x00000001 (1)
#>

if ($Script:IsDomainController) {
    Write-Verbose "Reason: Domain Controller"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
    Name = "RestrictRemoteClients"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params