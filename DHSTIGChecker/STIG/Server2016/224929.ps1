<#
Rule Title: Users must be prompted to authenticate when the system wakes from sleep (on battery).
Severity: medium
Vuln ID: V-224929
STIG ID: WN16-CC-000210

Discussion:
A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (on battery).


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\

Value Name: DCSettingIndex

Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
