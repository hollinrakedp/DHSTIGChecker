# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253256
Rule ID:    SV-253256r877465_rule
STIG ID:    WN11-00-000015
Legacy:     
Rule Title: Windows 11 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.
Discussion:
UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot. UEFI is required to support additional security features in Windows 11, including virtualization-based Security and Credential Guard. Systems with UEFI that are operating in Legacy BIOS mode will not support these security features.


Check Content:
For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Verify the system firmware is configured to run in UEFI mode, not Legacy BIOS.

Run "System Information".

Under "System Summary", if "BIOS Mode" does not display "UEFI", this is a finding.
#>

if ($Script:isVDI) {
    if (!($Script:VDIPersist)) {
        Write-Verbose "Reason: Non-Persistent VDI"
        return "Not Applicable"
    }
}

if ($Script:ComputerInfo.BiosFirmwareType -like "Uefi") {
    $true
}
else {
    $false
}