# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-220715
Rule ID:    SV-220715r890423_rule
STIG ID:    WN10-00-000085
Legacy:     V-63367; SV-77857
Rule Title: Standard local user accounts must not exist on a system in a domain.
Discussion:
To minimize potential points of attack, local user accounts, other than built-in accounts and local administrator accounts, must not exist on a workstation in a domain. Users must log on to workstations in a domain with their domain accounts.


Check Content:
For standalone or nondomain-joined systems, this is Not Applicable.

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

# PARTIAL
if (!($IsDomainJoined)) {
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

return "Not Reviewed"