# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253426
Rule ID:    SV-253426r829362_rule
STIG ID:    WN11-EP-000310
Legacy:     
Rule Title: Windows 11 Kernel (Direct Memory Access) DMA Protection must be enabled.
Discussion:
Kernel DMA Protection to protect PCs against drive-by Direct Memory Access (DMA) attacks using PCI hot plug devices connected to Thunderbolt 3 ports. Drive-by DMA attacks can lead to disclosure of sensitive information residing on a PC, or even injection of malware that allows attackers to bypass the lock screen or control PCs remotely.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Kernel DMA Protection

Value Name: DeviceEnumerationPolicy
Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection"
    Name          = "DeviceEnumerationPolicy"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params