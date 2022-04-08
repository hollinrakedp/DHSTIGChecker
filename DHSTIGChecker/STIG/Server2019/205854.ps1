<#
Rule Title: Windows Server 2019 FTP servers must be configured to prevent access to the system drive.
Severity: medium
Vuln ID: V-205854
STIG ID: WN19-00-000430

Discussion:
The FTP service allows remote users to access shared files and directories that could provide access to system resources and compromise the system, especially if the user can gain access to the root directory of the boot drive.


Check Content:
If FTP is not installed on the system, this is NA.

Open "Internet Information Services (IIS) Manager".

Select "Sites" under the server name.

For any sites with a Binding that lists FTP, right-click the site and select "Explore".

If the site is not defined to a specific folder for shared FTP resources, this is a finding.

If the site includes any system areas such as root of the drive, Program Files, or Windows directories, this is a finding.

#>
return 'Not Reviewed'
