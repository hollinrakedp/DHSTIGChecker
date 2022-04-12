<#
Rule Title: NTLM must be prevented from falling back to a Null session.
Severity: medium
Vuln ID: V-225050
STIG ID: WN16-SO-000330

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