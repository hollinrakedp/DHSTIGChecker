# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205689
Rule ID:    SV-205689r569188_rule
STIG ID:    WN19-CC-000160
Legacy:     V-93405; SV-103491
Rule Title: Windows Server 2019 printing over HTTP must be turned off.
Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system.

This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Printers\

Value Name: DisableHTTPPrinting

Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
    Name = "DisableHTTPPrinting"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params