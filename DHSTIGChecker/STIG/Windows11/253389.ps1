# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253389
Rule ID:    SV-253389r829251_rule
STIG ID:    WN11-CC-000195
Legacy:     
Rule Title: Enhanced anti-spoofing for facial recognition must be enabled on Windows 11.
Discussion:
Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support it.


Check Content:
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