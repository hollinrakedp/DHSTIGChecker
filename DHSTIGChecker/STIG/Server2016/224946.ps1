<#
Rule Title: Remote Desktop Services must always prompt a client for passwords upon connection.
Severity: medium
Vuln ID: V-224946
STIG ID: WN16-CC-000390

Discussion:
This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.

Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fPromptForPassword

Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
