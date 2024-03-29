# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253278
Rule ID:    SV-253278r828918_rule
STIG ID:    WN11-00-000115
Legacy:     
Rule Title: The Telnet Client must not be installed on the system.
Discussion:
The "Telnet Client" is not installed by default. Some protocols and services do not support required security features, such as encrypting passwords or traffic.


Check Content:
Verify Telnet Client has not been installed.

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