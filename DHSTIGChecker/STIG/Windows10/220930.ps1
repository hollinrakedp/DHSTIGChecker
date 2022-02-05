<#
Rule Title: Anonymous enumeration of shares must be restricted.
Severity: high
Vuln ID: V-220930
STIG ID: WN10-SO-000150

Discussion:
Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "RestrictAnonymous"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params