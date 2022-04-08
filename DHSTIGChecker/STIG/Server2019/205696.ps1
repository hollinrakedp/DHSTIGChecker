<#
Rule Title: Windows Server 2019 local users on domain-joined member servers must not be enumerated.
Severity: medium
Vuln ID: V-205696
STIG ID: WN19-MS-000030

Discussion:
The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.


Check Content:
This applies to member servers. For domain controllers and standalone systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0x00000000 (0)

#>
return 'Not Reviewed'
