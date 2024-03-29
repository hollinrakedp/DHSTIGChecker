# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205843
Rule ID:    SV-205843r860027_rule
STIG ID:    WN19-AU-000020
Legacy:     V-93185; SV-103273
Rule Title: Windows Server 2019 must, at a minimum, offload audit records of interconnected systems in real time and offload standalone or nondomain-joined systems weekly.
Discussion:
Protection of log data includes ensuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.


Check Content:
Verify the audit records, at a minimum, are offloaded for interconnected systems in real time and offloaded for standalone or nondomain-joined systems weekly. 

If they are not, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
