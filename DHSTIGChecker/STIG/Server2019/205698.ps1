# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205698
Rule ID:    SV-205698r569188_rule
STIG ID:    WN19-00-000360
Legacy:     V-93423; SV-103509
Rule Title: Windows Server 2019 must not have the Telnet Client installed.
Discussion:
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.


Check Content:
Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq Telnet-Client".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
