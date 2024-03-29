# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225047
Rule ID:    SV-225047r569186_rule
STIG ID:    WN16-SO-000290
Legacy:     V-73673; SV-88337
Rule Title: Windows Server 2016 must be configured to prevent anonymous users from having the same permissions as the Everyone group.
Discussion:
Access by anonymous users must be restricted. If this setting is enabled, anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "EveryoneIncludesAnonymous"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params