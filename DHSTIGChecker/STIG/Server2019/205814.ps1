# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205814
Rule ID:    SV-205814r877039_rule
STIG ID:    WN19-MS-000040
Legacy:     V-93453; SV-103539
Rule Title: Windows Server 2019 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone or nondomain-joined systems.
Discussion:
Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.


Check Content:
This applies to member servers and standalone or nondomain-joined systems. It is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows NT\Rpc\

Value Name:  RestrictRemoteClients

Type:  REG_DWORD
Value:  0x00000001 (1)
#>

if ($Script:IsDomainController) {
    "Not Applicable"
}
else {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
        Name          = "RestrictRemoteClients"
        ExpectedValue = 1
    }
    
    Compare-RegKeyValue @Params
}