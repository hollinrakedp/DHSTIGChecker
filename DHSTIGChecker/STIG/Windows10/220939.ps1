# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220939
Rule ID:    SV-220939r569187_rule
STIG ID:    WN10-SO-000210
Legacy:     V-63803; SV-78293
Rule Title: The system must be configured to the required LDAP client signing level.
Discussion:
This setting controls the signing requirements for LDAP clients.  This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\LDAP\

Value Name: LDAPClientIntegrity

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\"
    Name          = "LDAPClientIntegrity"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params