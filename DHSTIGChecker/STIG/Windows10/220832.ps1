<#
Rule Title: Administrator accounts must not be enumerated during elevation.
Severity: medium
Vuln ID: V-220832
STIG ID: WN10-CC-000200

Discussion:
Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user.  This setting configures the system to always require users to type in a username and password to elevate a running application.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\

Value Name: EnumerateAdministrators

Value Type: REG_DWORD
Value: 0

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"
    Name = "EnumerateAdministrators"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params