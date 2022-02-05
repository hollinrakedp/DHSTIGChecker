<#
Rule Title: The system must be configured to prevent anonymous users from having the same rights as the Everyone group.
Severity: medium
Vuln ID: V-220931
STIG ID: WN10-SO-000160

Discussion:
Access by anonymous users must be restricted.  If this setting is enabled, then anonymous users have the same rights and permissions as the built-in Everyone group.  Anonymous users must not have these permissions or rights.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "EveryoneIncludesAnonymous"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params