<#
Rule Title: Windows Server 2019 must not have the Telnet Client installed.
Severity: medium
Vuln ID: V-205698
STIG ID: WN19-00-000360

Discussion:
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.


Check Content:
Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq Telnet-Client".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.

#>
return 'Not Reviewed'
