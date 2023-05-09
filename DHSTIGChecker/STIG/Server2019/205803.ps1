<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   medium
Vuln ID:    V-205803
Rule ID:    SV-205803r860026_rule
STIG ID:    WN19-00-000220
Legacy:     V-93203; SV-103291
Rule Title: Windows Server 2019 system files must be monitored for unauthorized changes.
Discussion:
Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.


Check Content:
Determine whether the system is monitored for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis.

If system files are not monitored for unauthorized changes, this is a finding.

A properly configured McAfee Application Control and Change Control (MACC) module will meet the requirement for file integrity checking.
#>

# INCOMPLETE
return 'Not Reviewed'
