# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225055
Rule ID:    SV-225055r569186_rule
STIG ID:    WN16-SO-000390
Legacy:     V-73693; SV-88357
Rule Title: Windows Server 2016 must be configured to at least negotiate signing for LDAP client signing.
Discussion:
This setting controls the signing requirements for LDAP clients. This must be set to "Negotiate signing" or "Require signing", depending on the environment and type of LDAP server in use.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\LDAP\

Value Name: LDAPClientIntegrity

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\"
    Name          = "LDAPClientIntegrity"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params