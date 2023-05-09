<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   medium
Vuln ID:    V-224840
Rule ID:    SV-224840r860017_rule
STIG ID:    WN16-00-000240
Legacy:     V-73265; SV-87917
Rule Title: System files must be monitored for unauthorized changes.
Discussion:
Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.


Check Content:
Determine if the system is monitored for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis.

A properly configured McAfee Application Control and Change Control (MACC) module will meet the requirement for file integrity checking.

If system files are not monitored for unauthorized changes, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
