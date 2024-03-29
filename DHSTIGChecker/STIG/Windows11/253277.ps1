# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253277
Rule ID:    SV-253277r828915_rule
STIG ID:    WN11-00-000110
Legacy:     
Rule Title: Simple TCP/IP Services must not be installed on the system.
Discussion:
"Simple TCP/IP Services" is not installed by default. Some protocols and services do not support required security features, such as encrypting passwords or traffic.


Check Content:
Verify Simple TCP/IP Services has not been installed.

Run "Services.msc".

If "Simple TCP/IP Services" is listed, this is a finding.
#>

$Local:Service = @()
$Local:Service += Get-Service -Name "simptcp" -ErrorAction SilentlyContinue

if ($Local:Service.Count -ne 0) {
    $false
}
else {
    $true
}