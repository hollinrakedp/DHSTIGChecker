<#
Rule Title: The system must notify the user when a Bluetooth device attempts to connect.
Severity: medium
Vuln ID: V-220736
STIG ID: WN10-00-000230

Discussion:
If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised


Check Content:
This is NA if the system does not have Bluetooth, or if Bluetooth is turned off per the organizations policy.

Search for "Bluetooth".
View Bluetooth Settings.
Select "More Bluetooth Options"
If "Alert me when a new Bluetooth device wants to connect" is not checked, this is a finding.

#>

if ($Script:HasBluetooth) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}