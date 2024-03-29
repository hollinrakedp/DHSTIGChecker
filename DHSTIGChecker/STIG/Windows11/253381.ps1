# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253381
Rule ID:    SV-253381r829227_rule
STIG ID:    WN11-CC-000150
Legacy:     
Rule Title: The user must be prompted for a password on resume from sleep (plugged in).
Discussion:
Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (plugged in).


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\

Value Name: ACSettingIndex

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
    Name = "ACSettingIndex"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params