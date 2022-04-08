<#
Rule Title: Windows Server 2019 Windows Remote Management (WinRM) service must not store RunAs credentials.
Severity: medium
Vuln ID: V-205810
STIG ID: WN19-CC-000520

Discussion:
Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.

Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

Value Name: DisableRunAs

Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
