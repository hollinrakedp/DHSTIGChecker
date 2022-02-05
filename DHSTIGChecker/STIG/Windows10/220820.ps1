<#
Rule Title: Local users on domain-joined computers must not be enumerated.
Severity: medium
Vuln ID: V-220820
STIG ID: WN10-CC-000130

Discussion:
The username is one part of logon credentials that could be used to gain access to a system.  Preventing the enumeration of users limits this information to authorized personnel.


Check Content:
This requirement is applicable to domain-joined systems, for standalone systems this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnumerateLocalUsers

Value Type: REG_DWORD
Value: 0

#>

if (!($IsDomainJoined)) {
    Write-Verbose "This check does not apply: Reason - Not Domain-Joined"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name = "EnumerateLocalUsers"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params