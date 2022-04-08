<#
Rule Title: Windows Server 2019 Windows Remote Management (WinRM) service must not use Basic authentication.
Severity: high
Vuln ID: V-205713
STIG ID: WN19-CC-000500

Discussion:
Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0x00000000 (0)

#>
return 'Not Reviewed'
