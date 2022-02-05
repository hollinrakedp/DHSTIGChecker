<#
Rule Title: Alternate operating systems must not be permitted on the same system.
Severity: medium
Vuln ID: V-220709
STIG ID: WN10-00-000055

Discussion:
Allowing other operating systems to run on a secure system may allow security to be circumvented.


Check Content:
Verify the system does not include other operating system installations.

Run "Advanced System Settings".
Select the "Advanced" tab.
Click the "Settings" button in the "Startup and Recovery" section.

If the drop-down list box "Default operating system:" shows any operating system other than Windows 10, this is a finding.

#>

'Not Reviewed'