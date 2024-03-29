# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253263
Rule ID:    SV-253263r828873_rule
STIG ID:    WN11-00-000040
Legacy:     
Rule Title: Windows 11 systems must be maintained at a supported servicing level.
Discussion:
Windows 11 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a Service. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

New versions with feature updates are planned to be released on a semi-annual basis with an estimated support timeframe of 18 to 30 months depending on the release. Support for previously released versions has been extended for Enterprise editions.

A separate servicing branch intended for special purpose systems is the Long-Term Servicing Channel (LTSC, formerly Branch - LTSB) which will receive security updates for 10 years but excludes feature updates.


Check Content:
Run "winver.exe".

If the "About Windows" dialog box does not display "Microsoft Windows 11 Version 21H2 (OS Build 22000.348)" or greater, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
