# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220721
Rule ID:    SV-220721r569187_rule
STIG ID:    WN10-00-000115
Legacy:     V-63385; SV-77875
Rule Title: The Telnet Client must not be installed on the system.
Discussion:
Some protocols and services do not support required security features, such as encrypting passwords or traffic.


Check Content:
The "Telnet Client" is not installed by default.  Verify it has not been installed.

Navigate to the Windows\System32 directory.

If the "telnet" application exists, this is a finding.
#>

$Local:Feature = Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient"

if ($Local:Feature.State -contains 'Enabled') {
    $false
}
else {
    $true
}