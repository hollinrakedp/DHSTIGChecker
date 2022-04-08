<#
Rule Title: Windows Server 2019 must not have Simple TCP/IP Services installed.
Severity: medium
Vuln ID: V-205680
STIG ID: WN19-00-000350

Discussion:
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.


Check Content:
Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq Simple-TCPIP".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.

#>
return 'Not Reviewed'
