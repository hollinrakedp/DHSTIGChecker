# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205697
Rule ID:    SV-205697r569188_rule
STIG ID:    WN19-00-000330
Legacy:     V-93421; SV-103507
Rule Title: Windows Server 2019 must not have the Microsoft FTP service installed unless required by the organization.
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

# INCOMPLETE
return 'Not Reviewed'
