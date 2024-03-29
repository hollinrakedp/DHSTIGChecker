# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205851
Rule ID:    SV-205851r793214_rule
STIG ID:    WN19-00-000120
Legacy:     V-93219; SV-103307
Rule Title: Windows Server 2019 must have a host-based intrusion detection or prevention system.
Discussion:
A properly configured Host-based Intrusion Detection System (HIDS) or Host-based Intrusion Prevention System (HIPS) provides another level of defense against unauthorized access to critical servers. With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources.


Check Content:
Determine whether there is a HIDS or HIPS on each server. 

If the HIPS component of ESS is installed and active on the host and the alerts of blocked activity are being logged and monitored, this meets the requirement. 

A HIDS device is not required on a system that has the role as the Network Intrusion Device (NID). However, this exception needs to be documented with the ISSO.

If a HIDS is not installed on the system, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
