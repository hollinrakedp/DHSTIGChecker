# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253380
Rule ID:    SV-253380r829224_rule
STIG ID:    WN11-CC-000145
Legacy:     
Rule Title: Users must be prompted for a password on resume from sleep (on battery).
Discussion:
Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (on battery).


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\

Value Name: DCSettingIndex

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
    Name = "DCSettingIndex"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params