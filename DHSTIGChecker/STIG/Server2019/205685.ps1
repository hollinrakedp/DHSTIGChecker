<#
Rule Title: Windows Server 2019 must not have Windows PowerShell 2.0 installed.
Severity: medium
Vuln ID: V-205685
STIG ID: WN19-00-000410

Discussion:
Windows PowerShell 5.x added advanced logging features that can provide additional detail when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.x script block logging feature.


Check Content:
Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq PowerShell-v2".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.

#>
return 'Not Reviewed'
