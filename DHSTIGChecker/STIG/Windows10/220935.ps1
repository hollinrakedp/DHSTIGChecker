<#
Rule Title: PKU2U authentication using online identities must be prevented.
Severity: medium
Vuln ID: V-220935
STIG ID: WN10-SO-000185

Discussion:
PKU2U is a peer-to-peer authentication protocol.   This setting prevents online identities from authenticating to domain-joined systems.  Authentication will be centrally managed with Windows user accounts.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\pku2u\

Value Name: AllowOnlineID

Value Type: REG_DWORD
Value: 0

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
    Name          = "AllowOnlineID"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params