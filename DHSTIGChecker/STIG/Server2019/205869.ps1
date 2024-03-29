# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205869
Rule ID:    SV-205869r569188_rule
STIG ID:    WN19-CC-000250
Legacy:     V-93257; SV-103345
Rule Title: Windows Server 2019 Telemetry must be configured to Security or Basic.
Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. "Basic" sends basic diagnostic and usage data and may be required to support some Microsoft services.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\

Value Name: AllowTelemetry

Type: REG_DWORD
Value: 0x00000000 (0) (Security), 0x00000001 (1) (Basic)
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