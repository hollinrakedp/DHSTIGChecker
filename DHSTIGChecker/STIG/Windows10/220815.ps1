# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220815
Rule ID:    SV-220815r569187_rule
STIG ID:    WN10-CC-000100
Legacy:     V-63615; SV-78105
Rule Title: Downloading print driver packages over HTTP must be prevented.
Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting prevents the computer from downloading print driver packages over HTTP.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Printers\

Value Name: DisableWebPnPDownload

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
    Name = "DisableWebPnPDownload"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params