# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224855
Rule ID:    SV-224855r569186_rule
STIG ID:    WN16-00-000400
Legacy:     V-73297; SV-87949
Rule Title: The TFTP Client must not be installed.
Discussion:
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.


Check Content:
Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq TFTP-Client".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
