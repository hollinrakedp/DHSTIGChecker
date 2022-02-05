<#
Rule Title: Bluetooth must be turned off unless approved by the organization.
Severity: medium
Vuln ID: V-220734
STIG ID: WN10-00-000210

Discussion:
If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.


Check Content:
This is NA if the system does not have Bluetooth.

Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.

Approval must be documented with the ISSO.

#>

if ($Script:HasBluetooth) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}