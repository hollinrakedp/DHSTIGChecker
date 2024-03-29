# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225050
Rule ID:    SV-225050r569186_rule
STIG ID:    WN16-SO-000330
Legacy:     V-73681; SV-88345
Rule Title: NTLM must be prevented from falling back to a Null session.
Discussion:
NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

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