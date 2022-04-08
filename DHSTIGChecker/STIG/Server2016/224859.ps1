<#
Rule Title: Windows PowerShell 2.0 must not be installed.
Severity: medium
Vuln ID: V-224859
STIG ID: WN16-00-000420

Discussion:
Windows PowerShell 5.0 added advanced logging features that can provide additional detail when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.0 script block logging feature.


Check Content:
Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq PowerShell-v2".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.

#>
return 'Not Reviewed'
