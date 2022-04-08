<#
Rule Title: Non-administrative accounts or groups must only have print permissions on printer shares.
Severity: low
Vuln ID: V-224836
STIG ID: WN16-00-000200

Discussion:
Windows shares are a means by which files, folders, printers, and other resources can be published for network users to access. Improper configuration can permit access to devices and data beyond a user's need.


Check Content:
Open "Devices and Printers".

If there are no printers configured, this is NA. (Exclude Microsoft Print to PDF and Microsoft XPS Document Writer, which do not support sharing.)

For each printer:

Right-click on the printer. 

Select "Printer Properties". 

Select the "Sharing" tab. 

If "Share this printer" is checked, select the "Security" tab.

If any standard user accounts or groups have permissions other than "Print", this is a finding.

The default is for the "Everyone" group to be given "Print" permission.

"All APPLICATION PACKAGES" and "CREATOR OWNER" are not standard user accounts.

#>
return 'Not Reviewed'
