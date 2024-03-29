# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253458
Rule ID:    SV-253458r829458_rule
STIG ID:    WN11-SO-000180
Legacy:     
Rule Title: NTLM must be prevented from falling back to a Null session.
Discussion:
NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\

Value Name: allownullsessionfallback

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\"
    Name          = "allownullsessionfallback"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params