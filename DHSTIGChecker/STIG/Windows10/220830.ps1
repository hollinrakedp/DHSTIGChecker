<#
Rule Title: Enhanced anti-spoofing for facial recognition must be enabled on Window 10.
Severity: medium
Vuln ID: V-220830
STIG ID: WN10-CC-000195

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