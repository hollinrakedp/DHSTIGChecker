<#
Rule Title: Windows 10 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.
Severity: medium
Vuln ID: V-220699
STIG ID: WN10-00-000015

Discussion:
UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot. UEFI is required to support additional security features in Windows 10, including Virtualization Based Security and Credential Guard. Systems with UEFI that are operating in Legacy BIOS mode will not support these security features.


Check Content:
For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Verify the system firmware is configured to run in UEFI mode, not Legacy BIOS.

Run "System Information".

Under "System Summary", if "BIOS Mode" does not display "UEFI", this is a finding.

#>

if ($Script:isVDI) {
    if (!($Script:VDIPersist)) {
        Write-Verbose "This check does not apply: Reason - Non-Persistent VDI"
        return "Not Applicable"
    }
}

if ($Script:ComputerInfo.BiosFirmwareType -like "Uefi") {
    $true
}
else {
    $false
}