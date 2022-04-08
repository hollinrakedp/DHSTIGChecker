<#
Rule Title: Windows Server 2019 must prevent NTLM from falling back to a Null session.
Severity: medium
Vuln ID: V-205917
STIG ID: WN19-SO-000270

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
return 'Not Reviewed'
