# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253455
Rule ID:    SV-253455r829449_rule
STIG ID:    WN11-SO-000160
Legacy:     
Rule Title: The system must be configured to prevent anonymous users from having the same rights as the Everyone group.
Discussion:
Access by anonymous users must be restricted. If this setting is enabled, then anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights.


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