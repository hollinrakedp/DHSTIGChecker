<#
Rule Title: Windows Telemetry must not be configured to Full.
Severity: medium
Vuln ID: V-220834
STIG ID: WN10-CC-000205

Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender and telemetry client settings. "Basic" sends basic diagnostic and usage data and may be required to support some Microsoft services. "Enhanced" includes additional information on how Windows and apps are used and advanced reliability data. Windows Analytics can use a "limited enhanced" level to provide information such as health data for devices.  This requires the configuration of an additional setting available with v1709 and later of Windows 10. 


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\

Value Name: AllowTelemetry

Type: REG_DWORD
Value: 0x00000000 (0) (Security)
0x00000001 (1) (Basic)

If an organization is using v1709 or later of Windows 10 this may be configured to "Enhanced" to support Windows Analytics. V-82145 must also be configured to limit the Enhanced diagnostic data to the minimum required by Windows Analytics. This registry value will then be 0x00000002 (2).

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

#Add If ($Enhanced)

#Incomplete
return "Not Reviewed"