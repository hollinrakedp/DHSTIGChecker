# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205682
Rule ID:    SV-205682r819711_rule
STIG ID:    WN19-00-000380
Legacy:     V-93391; SV-103477
Rule Title: Windows Server 2019 must not have the Server Message Block (SMB) v1 protocol installed.
Discussion:
SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks and is not FIPS compliant.


Check Content:
Different methods are available to disable SMBv1 on Windows Server 2019. This is the preferred method; however, if WN19-00-000390 and WN19-00-000400 are configured, this is NA.

Open "Windows PowerShell" with elevated privileges (run as administrator).

Enter "Get-WindowsFeature -Name FS-SMB1".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
