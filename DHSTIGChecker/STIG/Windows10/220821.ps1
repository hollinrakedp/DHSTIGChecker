# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220821
Rule ID:    SV-220821r851986_rule
STIG ID:    WN10-CC-000145
Legacy:     V-63645; SV-78135
Rule Title: Users must be prompted for a password on resume from sleep (on battery).
Discussion:
Authentication must always be required when accessing a system.  This setting ensures the user is prompted for a password on resume from sleep (on battery).


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