<#
Rule Title: Audit records must be backed up to a different system or media than the system being audited.
Severity: medium
Vuln ID: V-224875
STIG ID: WN16-AU-000010

Discussion:
Protection of log data includes assuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.


Check Content:
Determine if a process to back up log data to a different system or media than the system being audited has been implemented.

If it has not, this is a finding.

#>
return 'Not Reviewed'
