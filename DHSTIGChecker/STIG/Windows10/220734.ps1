# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220734
Rule ID:    SV-220734r569187_rule
STIG ID:    WN10-00-000210
Legacy:     V-72765; SV-87403
Rule Title: Bluetooth must be turned off unless approved by the organization.
Discussion:
If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.


Check Content:
This is NA if the system does not have Bluetooth.

Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.

Approval must be documented with the ISSO.
#>

# PARTIAL
if ($Script:HasBluetooth) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}