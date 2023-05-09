<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   low
Vuln ID:    V-224865
Rule ID:    SV-224865r569186_rule
STIG ID:    WN16-00-000480
Legacy:     V-90357; SV-101007
Rule Title: Windows 2016 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.
Discussion:
UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot. UEFI is required to support additional security features in Windows Server 2016, including Virtualization Based Security and Credential Guard. Systems with UEFI that are operating in "Legacy BIOS" mode will not support these security features.


Check Content:
Some older systems may not have UEFI firmware. This is currently a CAT III; it will be raised in severity at a future date when broad support of Windows hardware and firmware requirements are expected to be met. Devices that have UEFI firmware must run in "UEFI" mode.

Verify the system firmware is configured to run in "UEFI" mode, not "Legacy BIOS".

Run "System Information".

Under "System Summary", if "BIOS Mode" does not display "UEFI", this is a finding.
#>

if ($Script:ComputerInfo.BiosFirmwareType -like "Uefi") {
    $true
}
else {
    $false
}