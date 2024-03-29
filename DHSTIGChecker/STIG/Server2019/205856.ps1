# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-205856
Rule ID:    SV-205856r569188_rule
STIG ID:    WN19-00-000460
Legacy:     V-93229; SV-103317
Rule Title: Windows Server 2019 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.
Discussion:
UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot. UEFI is required to support additional security features in Windows, including Virtualization Based Security and Credential Guard. Systems with UEFI that are operating in "Legacy BIOS" mode will not support these security features.


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