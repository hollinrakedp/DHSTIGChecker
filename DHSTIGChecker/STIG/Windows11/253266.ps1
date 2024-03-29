# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253266
Rule ID:    SV-253266r828882_rule
STIG ID:    WN11-00-000055
Legacy:     
Rule Title: Alternate operating systems must not be permitted on the same system.
Discussion:
Allowing other operating systems to run on a secure system may allow security to be circumvented.


Check Content:
Verify the system does not include other operating system installations.

Run "Advanced System Settings".
Select the "Advanced" tab.
Click the "Settings" button in the "Startup and Recovery" section.

If the drop-down list box "Default operating system:" shows any operating system other than Windows 11, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
