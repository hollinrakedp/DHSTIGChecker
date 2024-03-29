# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205917
Rule ID:    SV-205917r569188_rule
STIG ID:    WN19-SO-000270
Legacy:     V-93297; SV-103385
Rule Title: Windows Server 2019 must prevent NTLM from falling back to a Null session.
Discussion:
NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\

Value Name: allownullsessionfallback

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\"
    Name          = "allownullsessionfallback"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params