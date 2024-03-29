# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253291
Rule ID:    SV-253291r828957_rule
STIG ID:    WN11-00-000210
Legacy:     
Rule Title: Bluetooth must be turned off unless approved by the organization.
Discussion:
If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.


Check Content:
This is NA if the system does not have Bluetooth.

Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.

Approval must be documented with the ISSO.
#>

# INCOMPLETE
return 'Not Reviewed'
