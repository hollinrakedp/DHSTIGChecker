# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220814
Rule ID:    SV-220814r569187_rule
STIG ID:    WN10-CC-000090
Legacy:     V-63609; SV-78099
Rule Title: Group Policy objects must be reprocessed even if they have not changed.
Discussion:
Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}

Value Name: NoGPOListChanges

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    Name = "NoGPOListChanges"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params