<#
Rule Title: Windows Server 2019 must not have the Microsoft FTP service installed unless required by the organization.
Severity: medium
Vuln ID: V-205697
STIG ID: WN19-00-000330

Discussion:
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.


Check Content:
If the server has the role of an FTP server, this is NA.

Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq Web-Ftp-Service".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.

If the system has the role of an FTP server, this must be documented with the ISSO.

#>
return 'Not Reviewed'
