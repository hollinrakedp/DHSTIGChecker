<#
Rule Title: Windows Server 2019 must, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.
Severity: medium
Vuln ID: V-205843
STIG ID: WN19-AU-000020

Discussion:
Protection of log data includes assuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.


Check Content:
Verify the audit records, at a minimum, are off-loaded for interconnected systems in real time and off-loaded for standalone systems weekly. 

If they are not, this is a finding.

#>
return 'Not Reviewed'
