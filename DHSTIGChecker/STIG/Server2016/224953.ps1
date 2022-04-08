<#
Rule Title: Users must be prevented from changing installation options.
Severity: medium
Vuln ID: V-224953
STIG ID: WN16-CC-000450

Discussion:
Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\

Value Name: EnableUserControl

Type: REG_DWORD
Value: 0x00000000 (0)

#>
return 'Not Reviewed'
