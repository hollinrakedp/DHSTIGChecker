<#
Rule Title: Anonymous enumeration of SAM accounts must not be allowed.
Severity: high
Vuln ID: V-220929
STIG ID: WN10-SO-000145

Discussion:
Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "RestrictAnonymousSAM"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params