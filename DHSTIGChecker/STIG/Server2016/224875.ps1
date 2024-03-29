# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224875
Rule ID:    SV-224875r877390_rule
STIG ID:    WN16-AU-000010
Legacy:     V-73401; SV-88053
Rule Title: Audit records must be backed up to a different system or media than the system being audited.
Discussion:
Protection of log data includes assuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.


Check Content:
Determine if a process to back up log data to a different system or media than the system being audited has been implemented.

If it has not, this is a finding.
#>

# MANUAL
return 'Not Reviewed'
