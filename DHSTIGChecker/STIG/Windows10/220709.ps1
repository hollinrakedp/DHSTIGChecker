# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220709
Rule ID:    SV-220709r569187_rule
STIG ID:    WN10-00-000055
Legacy:     V-63355; SV-77845
Rule Title: Alternate operating systems must not be permitted on the same system.
Discussion:
Allowing other operating systems to run on a secure system may allow security to be circumvented.


Check Content:
Verify the system does not include other operating system installations.

Run "Advanced System Settings".
Select the "Advanced" tab.
Click the "Settings" button in the "Startup and Recovery" section.

If the drop-down list box "Default operating system:" shows any operating system other than Windows 10, this is a finding.
#>

# MANUAL
return 'Not Reviewed'
