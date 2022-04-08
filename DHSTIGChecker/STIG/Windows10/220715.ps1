<#
Rule Title: Standard local user accounts must not exist on a system in a domain.
Severity: low
Vuln ID: V-220715
STIG ID: WN10-00-000085

Discussion:
To minimize potential points of attack, local user accounts, other than built-in accounts and local administrator accounts, must not exist on a workstation in a domain.  Users must log onto workstations in a domain with their domain accounts.


Check Content:
Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Users.

If local users other than the accounts listed below exist on a workstation in a domain, this is a finding.

Built-in Administrator account (Disabled)
Built-in Guest account (Disabled)
Built-in DefaultAccount (Disabled)
Built-in defaultuser0 (Disabled)
Built-in WDAGUtilityAccount (Disabled)
Local administrator account(s)

All of the built-in accounts may not exist on a system, depending on the Windows 10 version.

#>

if (!($IsDomainJoined)) {
    Write-Verbose "This check does not apply: Reason - Not Domain-Joined"
    return "Not Applicable"
}

#Incomplete
return "Not Reviewed"