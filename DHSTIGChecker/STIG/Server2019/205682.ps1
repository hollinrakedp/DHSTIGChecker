<#
Rule Title: Windows Server 2019 must not the Server Message Block (SMB) v1 protocol installed.
Severity: medium
Vuln ID: V-205682
STIG ID: WN19-00-000380

Discussion:
SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks and is not FIPS compliant.


Check Content:
Different methods are available to disable SMBv1 on Windows Server 2019.  This is the preferred method, however if WN19-00-000390 and WN19-00-000400 are configured, this is NA.

Open "Windows PowerShell" with elevated privileges (run as administrator).

Enter "Get-WindowsFeature -Name FS-SMB1".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.

#>
return 'Not Reviewed'
