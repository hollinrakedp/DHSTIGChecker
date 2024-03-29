# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220830
Rule ID:    SV-220830r569187_rule
STIG ID:    WN10-CC-000195
Legacy:     V-63677; SV-78167
Rule Title: Enhanced anti-spoofing for facial recognition must be enabled on Window 10.
Discussion:
Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support it.


Check Content:
Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\

Value Name: EnhancedAntiSpoofing

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\"
    Name = "EnhancedAntiSpoofing"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params