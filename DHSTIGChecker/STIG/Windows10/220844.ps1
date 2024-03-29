# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220844
Rule ID:    SV-220844r569187_rule
STIG ID:    WN10-CC-000250
Legacy:     V-63713; SV-78203
Rule Title: The Windows Defender SmartScreen filter for Microsoft Edge must be enabled.
Discussion:
The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially malicious websites.


Check Content:
This is applicable to unclassified systems, for other systems this is NA.

Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\

Value Name: EnabledV9

Type: REG_DWORD
Value: 0x00000001 (1)
#>

# No check for LTSB/LTSC
$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\"
    Name = "EnabledV9"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params