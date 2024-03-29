# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220932
Rule ID:    SV-220932r569187_rule
STIG ID:    WN10-SO-000165
Legacy:     V-63759; SV-78249
Rule Title: Anonymous access to Named Pipes and Shares must be restricted.
Discussion:
Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access.  This setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously" and "Network access: Shares that can be accessed anonymously",  both of which must be blank under other requirements.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: RestrictNullSessAccess

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
    Name          = "RestrictNullSessAccess"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params