<#
Rule Title: Administrator accounts must not be enumerated during elevation.
Severity: medium
Vuln ID: V-224935
STIG ID: WN16-CC-000280

Discussion:
Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\

Value Name: EnumerateAdministrators

Type: REG_DWORD
Value: 0x00000000 (0)

#>
return 'Not Reviewed'
