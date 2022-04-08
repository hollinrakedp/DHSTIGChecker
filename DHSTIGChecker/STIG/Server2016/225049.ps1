<#
Rule Title: Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.
Severity: medium
Vuln ID: V-225049
STIG ID: WN16-SO-000320

Discussion:
Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously versus using the computer identity.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\

Value Name: UseMachineId

Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
