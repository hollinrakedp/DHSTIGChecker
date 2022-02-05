<#
Rule Title: If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows Analytics.
Severity: medium
Vuln ID: V-220833
STIG ID: WN10-CC-000204

Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Enhanced" level for telemetry includes additional information beyond "Security" and "Basic" on how Windows and apps are used and advanced reliability data. Windows Analytics can use a "limited enhanced" level to provide information such as health data for devices.


Check Content:
This setting requires v1709 or later of Windows 10; it is NA for prior versions.

If "Enhanced" level is enabled for telemetry, this must be configured. If "Security" or "Basic" are configured, this is NA. (See V-220834).

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\

Value Name: LimitEnhancedDiagnosticDataWindowsAnalytics

Type: REG_DWORD
Value: 0x00000001 (1)

#>

if ($Script:ComputerInfo.WindowsVersion -lt 1709) {
    Write-Verbose "This check does not apply: Reason - Version is < 1709"
    return 'Not Applicable'
}

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
    Name = "LimitEnhancedDiagnosticDataWindowsAnalytics"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params