# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253257
Rule ID:    SV-253257r877465_rule
STIG ID:    WN11-00-000020
Legacy:     
Rule Title: Secure Boot must be enabled on Windows 11 systems.
Discussion:
Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is required to support additional security features in Windows 11, including virtualization-based Security and Credential Guard. If Secure Boot is turned off, these security features will not function.


Check Content:
Verify the system firmware is configured for Secure Boot.

For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is a finding.
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