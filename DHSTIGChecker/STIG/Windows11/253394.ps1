# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253394
Rule ID:    SV-253394r829266_rule
STIG ID:    WN11-CC-000206
Legacy:     
Rule Title: Windows Update must not obtain updates from other PCs on the internet.
Discussion:
Windows 11 allows Windows Update to obtain updates from additional sources instead of Microsoft. In addition to Microsoft, updates can be obtained from and sent to PCs on the local network as well as on the Internet. This is part of the Windows Update trusted process, however to minimize outside exposure, obtaining updates from or sending to systems on the internet must be prevented.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\

Value Name: DODownloadMode

Value Type: REG_DWORD
Value: 0x00000000 (0) - No peering (HTTP Only)
0x00000001 (1) - Peers on same NAT only (LAN)
0x00000002 (2) - Local Network / Private group peering (Group)
0x00000063 (99) - Simple download mode, no peering (Simple)
0x00000064 (100) - Bypass mode, Delivery Optimization not used (Bypass)

A value of 0x00000003 (3), Internet, is a finding.

Standalone systems (configured in Settings):
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\

Value Name: DODownloadMode

Value Type: REG_DWORD
Value: 0x00000000 (0) - Off
0x00000001 (1) - LAN
#>

if ($Script:IsDomainJoined) {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\"
        Name          = "DODownloadMode"
        ExpectedValue = 3
        Comparison    = 'ne'
    }

    Compare-RegKeyValue @Params
}
else {
    $Local:Results = @()
    $Local:ValidValues = 0, 1

    foreach ($Value in $Local:ValidValues) {
        $Params = @{
            Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\"
            Name          = "DODownloadMode"
            ExpectedValue = $Value
        }
    
        $Local:Results += Compare-RegKeyValue @Params
    }

    if ($Local:Results -contains $true) {
        $true
    }
    else {
        $false
    }
}