<#
Rule Title: The Server Message Block (SMB) v1 protocol must be disabled on the system.
Severity: medium
Vuln ID: V-220729
STIG ID: WN10-00-000160

Discussion:
SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.

Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no longer a supported operating system. Some older Network Attached Storage (NAS) devices may only support SMBv1.


Check Content:
Different methods are available to disable SMBv1 on Windows 10.  This is the preferred method, however if V-220730 and V-220731 are configured, this is NA.

Run "Windows PowerShell" with elevated privileges (run as administrator).

Enter the following:
Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol

If "State : Enabled" is returned, this is a finding.

Alternately:
Search for "Features".

Select "Turn Windows features on or off".

If "SMB 1.0/CIFS File Sharing Support" is selected, this is a finding.

#>

$Local:Feature = Get-WindowsOptionalFeature -Online -Verbose:$false -FeatureName "SMB1Protocol"

if ($Local:Feature.State -contains 'Enabled') {
    $false
}
else {
    $true
}