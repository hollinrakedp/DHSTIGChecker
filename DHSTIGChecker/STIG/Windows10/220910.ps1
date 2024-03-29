# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220910
Rule ID:    SV-220910r569187_rule
STIG ID:    WN10-SO-000015
Legacy:     V-63617; SV-78107
Rule Title: Local accounts with blank passwords must be restricted to prevent access from the network.
Discussion:
An account without a password can allow unauthorized access to a system as only the username would be required.  Password policies should prevent accounts with blank passwords from existing on a system.  However, if a local account with a blank password did exist, enabling this setting will prevent network access, limiting the account to local console logon only.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: LimitBlankPasswordUse

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "LimitBlankPasswordUse"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params