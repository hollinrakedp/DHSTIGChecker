# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220736
Rule ID:    SV-220736r569187_rule
STIG ID:    WN10-00-000230
Legacy:     V-72769; SV-87407
Rule Title: The system must notify the user when a Bluetooth device attempts to connect.
Discussion:
If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised


Check Content:
This is NA if the system does not have Bluetooth, or if Bluetooth is turned off per the organizations policy.

Search for "Bluetooth".
View Bluetooth Settings.
Select "More Bluetooth Options"
If "Alert me when a new Bluetooth device wants to connect" is not checked, this is a finding.
#>

# PARTIAL
if ($Script:HasBluetooth) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}