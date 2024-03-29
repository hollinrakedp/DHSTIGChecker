# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220816
Rule ID:    SV-220816r569187_rule
STIG ID:    WN10-CC-000105
Legacy:     V-63621; SV-78111
Rule Title: Web publishing and online ordering wizards must be prevented from downloading a list of providers.
Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting prevents Windows from downloading a list of providers for the Web publishing and online ordering wizards.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoWebServices

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
    Name = "NoWebServices"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params