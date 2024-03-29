# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253392
Rule ID:    SV-253392r829260_rule
STIG ID:    WN11-CC-000204
Legacy:     
Rule Title: Enhanced diagnostic data must be limited to the minimum required to support Windows Analytics.
Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Enhanced" level for telemetry includes additional information beyond "Security" and "Basic" on how Windows and apps are used and advanced reliability data. Windows Analytics can use a "limited enhanced" level to provide information such as health data for devices.


Check Content:
If "Enhanced" level is enabled for telemetry, this must be configured. If "Security" or "Basic" are configured, this is NA. (See WN11-CC-000205).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\

Value Name: LimitEnhancedDiagnosticDataWindowsAnalytics

Type: REG_DWORD
Value: 0x00000001 (1)
#>

# INCOMPLETE
return 'Not Reviewed'
