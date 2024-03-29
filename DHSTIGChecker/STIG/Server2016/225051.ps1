# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225051
Rule ID:    SV-225051r569186_rule
STIG ID:    WN16-SO-000340
Legacy:     V-73683; SV-88347
Rule Title: PKU2U authentication using online identities must be prevented.
Discussion:
PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\pku2u\

Value Name: AllowOnlineID

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
    Name          = "AllowOnlineID"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params