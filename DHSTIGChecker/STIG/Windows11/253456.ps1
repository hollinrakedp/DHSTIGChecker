# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253456
Rule ID:    SV-253456r829452_rule
STIG ID:    WN11-SO-000165
Legacy:     
Rule Title: Anonymous access to Named Pipes and Shares must be restricted.
Discussion:
Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously" and "Network access: Shares that can be accessed anonymously", both of which must be blank under other requirements.


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