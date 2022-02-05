<#
Rule Title: Simple Network Management Protocol (SNMP) must not be installed on the system.
Severity: medium
Vuln ID: V-220719
STIG ID: WN10-00-000105

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