# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224856
Rule ID:    SV-224856r569186_rule
STIG ID:    WN16-00-000410
Legacy:     V-73299; SV-87951
Rule Title: The Server Message Block (SMB) v1 protocol must be uninstalled.
Discussion:
SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks and is not FIPS compliant.


Check Content:
Different methods are available to disable SMBv1 on Windows 2016.  This is the preferred method, however if V-78123 and V-78125 are configured, this is NA.

Open "Windows PowerShell" with elevated privileges (run as administrator).

Enter "Get-WindowsFeature -Name FS-SMB1".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
