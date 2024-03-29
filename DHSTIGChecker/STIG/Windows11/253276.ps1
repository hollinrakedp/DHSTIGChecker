# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253276
Rule ID:    SV-253276r828912_rule
STIG ID:    WN11-00-000105
Legacy:     
Rule Title: Simple Network Management Protocol (SNMP) must not be installed on the system.
Discussion:
"SNMP" is not installed by default. Some protocols and services do not support required security features, such as encrypting passwords or traffic.


Check Content:
Verify SNMP has not been installed.

Navigate to the Windows\System32 directory.

If the "SNMP" application exists, this is a finding.
#>

$SNMP = Get-WindowsCapability -Online -Name "SNMP*"

if ($SNMP.State -contains "Installed") {
    $false
}
else {
    $true
}