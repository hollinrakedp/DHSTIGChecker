<#
Rule Title: System files must be monitored for unauthorized changes.
Severity: medium
Vuln ID: V-224840
STIG ID: WN16-00-000240

Discussion:
Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.


Check Content:
Determine whether the system is monitored for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis.

A properly configured and approved DoD ESS solution that supports a File Integrity Monitor (FIM) module will meet the requirement for file integrity checking. 

If system files are not monitored for unauthorized changes, this is a finding.

#>
return 'Not Reviewed'
