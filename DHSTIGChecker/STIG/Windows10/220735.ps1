<#
Rule Title: Bluetooth must be turned off when not in use.
Severity: medium
Vuln ID: V-220735
STIG ID: WN10-00-000220

Discussion:
If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.


Check Content:
This is NA if the system does not have Bluetooth.

Verify the organization has a policy to turn off Bluetooth when not in use and personnel are trained. If it does not, this is a finding.

#>

if ($Script:HasBluetooth) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}