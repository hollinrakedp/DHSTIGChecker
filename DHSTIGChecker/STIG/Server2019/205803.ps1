# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205803
Rule ID:    SV-205803r890522_rule
STIG ID:    WN19-00-000220
Legacy:     V-93203; SV-103291
Rule Title: Windows Server 2019 system files must be monitored for unauthorized changes.
Discussion:
Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.


Check Content:
Determine whether the system is monitored for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis.

If system files are not monitored for unauthorized changes, this is a finding.

An approved and properly configured solution will contain both a list of baselines that includes all system file locations and a file comparison task that is scheduled to run at least weekly.
#>

# INCOMPLETE
return 'Not Reviewed'
