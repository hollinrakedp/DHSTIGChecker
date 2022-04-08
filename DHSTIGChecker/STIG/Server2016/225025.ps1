<#
Rule Title: Local accounts with blank passwords must be restricted to prevent access from the network.
Severity: high
Vuln ID: V-225025
STIG ID: WN16-SO-000020

Discussion:
An account without a password can allow unauthorized access to a system as only the username would be required. Password policies should prevent accounts with blank passwords from existing on a system. However, if a local account with a blank password does exist, enabling this setting will prevent network access, limiting the account to local console logon only.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: LimitBlankPasswordUse

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
