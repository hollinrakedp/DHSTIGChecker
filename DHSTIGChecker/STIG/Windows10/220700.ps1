# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-220700
Rule ID:    SV-220700r569187_rule
STIG ID:    WN10-00-000020
Legacy:     V-77085; SV-91781
Rule Title: Secure Boot must be enabled on Windows 10 systems.
Discussion:
Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is required to support additional security features in Windows 10, including Virtualization Based Security and Credential Guard. If Secure Boot is turned off, these security features will not function.


Check Content:
Some older systems may not have UEFI firmware. This is currently a CAT III; it will be raised in severity at a future date when broad support of Windows 10 hardware and firmware requirements are expected to be met. Devices that have UEFI firmware must have Secure Boot enabled. 

For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is finding.
#>

if ($Script:isVDI) {
    if (!($Script:VDIPersist)) {
        Write-Verbose "Reason: Non-Persistent VDI"
        return "Not Applicable"
    }
}

$SecureBoot = Confirm-SecureBootUEFI
switch ($SecureBoot) {
    "Cmdlet not supported on this platform." {
        Write-Verbose "Reason: System does not support SecureBoot"
        $SecureBoot = $false 
    }
}
$SecureBoot