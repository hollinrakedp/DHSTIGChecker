# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-224864
Rule ID:    SV-224864r569186_rule
STIG ID:    WN16-00-000470
Legacy:     V-90355; SV-101005
Rule Title: Secure Boot must be enabled on Windows Server 2016 systems.
Discussion:
Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is required to support additional security features in Windows Server 2016, including Virtualization Based Security and Credential Guard. If Secure Boot is turned off, these security features will not function.


Check Content:
Some older systems may not have UEFI firmware. This is currently a CAT III; it will be raised in severity at a future date when broad support of Windows hardware and firmware requirements are expected to be met. Devices that have UEFI firmware must have Secure Boot enabled. 

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is a finding.
#>

$SecureBoot = Confirm-SecureBootUEFI
switch ($SecureBoot) {
    "Cmdlet not supported on this platform." {
        Write-Verbose "Reason: System does not support SecureBoot"
        $SecureBoot = $false 
    }
}
$SecureBoot