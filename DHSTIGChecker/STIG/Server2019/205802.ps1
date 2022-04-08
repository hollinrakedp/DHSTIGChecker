<#
Rule Title: Windows Server 2019 must disable the Windows Installer Always install with elevated privileges option.
Severity: high
Vuln ID: V-205802
STIG ID: WN19-CC-000430

Discussion:
Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\

Value Name: AlwaysInstallElevated

Type: REG_DWORD
Value: 0x00000000 (0)

#>
return 'Not Reviewed'
