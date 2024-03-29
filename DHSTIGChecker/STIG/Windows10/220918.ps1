# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-220918
Rule ID:    SV-220918r569187_rule
STIG ID:    WN10-SO-000055
Legacy:     V-63661; SV-78151
Rule Title: The maximum age for machine account passwords must be configured to 30 days or less.
Discussion:
Computer account passwords are changed automatically on a regular basis.  This setting controls the maximum password age that a machine account may have.  This setting must be set to no more than 30 days, ensuring the machine changes its password monthly.


Check Content:
This is the default configuration for this setting (30 days).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: MaximumPasswordAge

Value Type: REG_DWORD
Value: 0x0000001e (30)  (or less, excluding 0)
#>

$Local:Results = @()

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    Name          = "MaximumPasswordAge"
    ExpectedValue = 30
    Comparison    = 'le'
}

$Local:Results += Compare-RegKeyValue @Params

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    Name          = "MaximumPasswordAge"
    ExpectedValue = 0
    Comparison    = "ne"
}

$Local:Results += Compare-RegKeyValue @Params

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}