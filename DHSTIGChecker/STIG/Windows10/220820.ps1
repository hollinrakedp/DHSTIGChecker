# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220820
Rule ID:    SV-220820r857194_rule
STIG ID:    WN10-CC-000130
Legacy:     V-63633; SV-78123
Rule Title: Local users on domain-joined computers must not be enumerated.
Discussion:
The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.


Check Content:
This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnumerateLocalUsers

Value Type: REG_DWORD
Value: 0
#>

if (!($IsDomainJoined)) {
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name = "EnumerateLocalUsers"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params