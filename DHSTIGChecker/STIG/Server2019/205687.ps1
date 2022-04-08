<#
Rule Title: Windows Server 2019 must have WDigest Authentication disabled.
Severity: medium
Vuln ID: V-205687
STIG ID: WN19-CC-000020

Discussion:
When the WDigest Authentication protocol is enabled, plain-text passwords are stored in the Local Security Authority Subsystem Service (LSASS), exposing them to theft. WDigest is disabled by default in Windows Server 2019. This setting ensures this is enforced.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\

Value Name:  UseLogonCredential

Type:  REG_DWORD
Value:  0x00000000 (0)

#>
return 'Not Reviewed'
