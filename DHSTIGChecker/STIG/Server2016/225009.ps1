# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225009
Rule ID:    SV-225009r857260_rule
STIG ID:    WN16-MS-000030
Legacy:     V-73533; SV-88187
Rule Title: Local users on domain-joined computers must not be enumerated.
Discussion:
The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.


Check Content:
This applies to member servers. For domain controllers and standalone or nondomain-joined systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0x00000000 (0)
#>

if ($Script:IsDomainController) {
    Write-Verbose "Reason: Domain Controller"
    return "Not Applicable"
}

if (!($Script:IsDomainJoined)) {
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name = "EnumerateLocalUsers"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params