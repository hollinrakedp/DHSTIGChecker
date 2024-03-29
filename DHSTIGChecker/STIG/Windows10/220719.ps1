# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220719
Rule ID:    SV-220719r569187_rule
STIG ID:    WN10-00-000105
Legacy:     V-63381; SV-77871
Rule Title: Simple Network Management Protocol (SNMP) must not be installed on the system.
Discussion:
Some protocols and services do not support required security features, such as encrypting passwords or traffic.


Check Content:
"SNMP" is not installed by default.  Verify it has not been installed.

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