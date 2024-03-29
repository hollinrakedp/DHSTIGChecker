# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220735
Rule ID:    SV-220735r569187_rule
STIG ID:    WN10-00-000220
Legacy:     V-72767; SV-87405
Rule Title: Bluetooth must be turned off when not in use.
Discussion:
If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.


Check Content:
This is NA if the system does not have Bluetooth.

Verify the organization has a policy to turn off Bluetooth when not in use and personnel are trained. If it does not, this is a finding.
#>

# PARTIAL
if ($Script:HasBluetooth) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}