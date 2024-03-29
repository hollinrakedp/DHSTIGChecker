# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-205857
Rule ID:    SV-205857r569188_rule
STIG ID:    WN19-00-000470
Legacy:     V-93231; SV-103319
Rule Title: Windows Server 2019 must have Secure Boot enabled.
Discussion:
Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is required to support additional security features in Windows, including Virtualization Based Security and Credential Guard. If Secure Boot is turned off, these security features will not function.


Check Content:
Some older systems may not have UEFI firmware. This is currently a CAT III; it will be raised in severity at a future date when broad support of Windows hardware and firmware requirements are expected to be met. Devices that have UEFI firmware must have Secure Boot enabled.  

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is a finding.

On server core installations, run the following PowerShell command:

Confirm-SecureBootUEFI

If a value of "True" is not returned, this is a finding.
#>

$SecureBoot = Confirm-SecureBootUEFI
switch ($SecureBoot) {
    "Cmdlet not supported on this platform." {
        Write-Verbose "Reason: System does not support SecureBoot"
        $SecureBoot = $false 
    }
}
$SecureBoot