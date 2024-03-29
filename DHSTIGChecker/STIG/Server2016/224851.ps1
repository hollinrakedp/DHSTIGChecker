# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224851
Rule ID:    SV-224851r569186_rule
STIG ID:    WN16-00-000360
Legacy:     V-73289; SV-87941
Rule Title: The Microsoft FTP service must not be installed unless required.
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
