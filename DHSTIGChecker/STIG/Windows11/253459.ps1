# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253459
Rule ID:    SV-253459r829461_rule
STIG ID:    WN11-SO-000185
Legacy:     
Rule Title: PKU2U authentication using online identities must be prevented.
Discussion:
PKU2U is a peer-to-peer authentication protocol.  This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\pku2u\

Value Name: AllowOnlineID

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
    Name          = "AllowOnlineID"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params