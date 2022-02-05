<#
Rule Title: Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.
Severity: medium
Vuln ID: V-220799
STIG ID: WN10-CC-000037

Discussion:
A compromised local administrator account can provide means for an attacker to move laterally between domain systems.

With User Account Control enabled, filtering the privileged token for built-in administrator accounts will prevent the elevated privileges of these accounts from being used over the network.


Check Content:
If the system is not a member of a domain, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LocalAccountTokenFilterPolicy

Value Type: REG_DWORD
Value: 0x00000000 (0)

#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "This check does not apply: Reason - Not Domain-Joined"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name = "LocalAccountTokenFilterPolicy"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params