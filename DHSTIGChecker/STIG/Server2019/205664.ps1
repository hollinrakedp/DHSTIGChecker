# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-205664
Rule ID:    SV-205664r569188_rule
STIG ID:    WN19-00-000180
Legacy:     V-92993; SV-103081
Rule Title: Windows Server 2019 non-administrative accounts or groups must only have print permissions on printer shares.
Discussion:
Windows shares are a means by which files, folders, printers, and other resources can be published for network users to access. Improper configuration can permit access to devices and data beyond a user's need.


Check Content:
Open "Printers & scanners" in "Settings".

If there are no printers configured, this is NA. (Exclude Microsoft Print to PDF and Microsoft XPS Document Writer, which do not support sharing.)

For each printer:

Select the printer and "Manage". 

Select "Printer Properties". 

Select the "Sharing" tab. 

If "Share this printer" is checked, select the "Security" tab.

If any standard user accounts or groups have permissions other than "Print", this is a finding.

The default is for the "Everyone" group to be given "Print" permission.

"All APPLICATION PACKAGES" and "CREATOR OWNER" are not standard user accounts.
#>

# INCOMPLETE
return 'Not Reviewed'
