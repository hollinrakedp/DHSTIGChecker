# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253393
Rule ID:    SV-253393r857208_rule
STIG ID:    WN11-CC-000205
Legacy:     
Rule Title: Windows Telemetry must not be configured to Full.
Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender and telemetry client settings. "Basic" sends basic diagnostic and usage data and may be required to support some Microsoft services. "Enhanced" includes additional information on how Windows and apps are used and advanced reliability data. Windows Analytics can use a "limited enhanced" level to provide information such as health data for devices.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\

Value Name: AllowTelemetry

Type: REG_DWORD
Value: 0x00000000 (0) (Security)
0x00000001 (1) (Basic)
#>

$Results = @()
$ValidValues = 0, 1

foreach ($Value in $ValidValues) {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
        Name          = "AllowTelemetry"
        ExpectedValue = $Value
    }

    $Results += Compare-RegKeyValue @Params
}

if ($Results -contains $true) {
    $true
}
else {
    $false
}