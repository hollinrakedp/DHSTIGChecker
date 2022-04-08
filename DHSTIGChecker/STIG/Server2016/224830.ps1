<#
Rule Title: Servers must have a host-based intrusion detection or prevention system.
Severity: medium
Vuln ID: V-224830
STIG ID: WN16-00-000140

Discussion:
A properly configured Host-based Intrusion Detection System (HIDS) or Host-based Intrusion Prevention System (HIPS) provides another level of defense against unauthorized access to critical servers. With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources.


Check Content:
Determine whether there is a HIDS or HIPS on each server. 

If the HIPS component of ESS is installed and active on the host and the alerts of blocked activity are being logged and monitored, this meets the requirement. 

A HIDS device is not required on a system that has the role as the Network Intrusion Device (NID). However, this exception needs to be documented with the ISSO.

If a HIDS is not installed on the system, this is a finding.

#>
return 'Not Reviewed'
