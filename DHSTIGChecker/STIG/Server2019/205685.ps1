# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205685
Rule ID:    SV-205685r569188_rule
STIG ID:    WN19-00-000410
Legacy:     V-93397; SV-103483
Rule Title: Windows Server 2019 must not have Windows PowerShell 2.0 installed.
Discussion:
Windows PowerShell 5.x added advanced logging features that can provide additional detail when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.x script block logging feature.


Check Content:
Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq PowerShell-v2".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
