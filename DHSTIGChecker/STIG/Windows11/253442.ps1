# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253442
Rule ID:    SV-253442r829410_rule
STIG ID:    WN11-SO-000055
Legacy:     
Rule Title: The maximum age for machine account passwords must be configured to 30 days or less.
Discussion:
Computer account passwords are changed automatically on a regular basis. This setting controls the maximum password age that a machine account may have. This setting must be set to no more than 30 days, ensuring the machine changes its password monthly.


Check Content:
(remove)This is the default configuration for this setting (30 days).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: MaximumPasswordAge

Value Type: REG_DWORD
Value: 0x0000001e (30) (or less, excluding 0)
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