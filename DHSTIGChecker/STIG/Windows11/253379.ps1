# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253379
Rule ID:    SV-253379r829221_rule
STIG ID:    WN11-CC-000130
Legacy:     
Rule Title: Local users on domain-joined computers must not be enumerated.
Discussion:
The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.


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
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name = "EnumerateLocalUsers"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params