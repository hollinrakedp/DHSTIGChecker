<#
Rule Title: Unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers.
Severity: medium
Vuln ID: V-225041
STIG ID: WN16-SO-000210

Discussion:
Some non-Microsoft SMB servers only support unencrypted (plain-text) password authentication. Sending plain-text passwords across the network when authenticating to an SMB server reduces the overall security of the environment. Check with the vendor of the SMB server to determine if there is a way to support encrypted password authentication.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name:  EnablePlainTextPassword

Value Type:  REG_DWORD
Value:  0x00000000 (0)

#>
return 'Not Reviewed'
