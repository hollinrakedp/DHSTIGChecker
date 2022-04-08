<#
Rule Title: The Telnet Client must not be installed.
Severity: medium
Vuln ID: V-224854
STIG ID: WN16-00-000390

Discussion:
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.


Check Content:
Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq Telnet-Client".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.

#>
return 'Not Reviewed'
