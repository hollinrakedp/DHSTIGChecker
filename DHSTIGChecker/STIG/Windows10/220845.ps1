# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220845
Rule ID:    SV-220845r569187_rule
STIG ID:    WN10-CC-000252
Legacy:     V-74417; SV-89091
Rule Title: Windows 10 must be configured to disable Windows Game Recording and Broadcasting.
Discussion:
Windows Game Recording and Broadcasting is intended for use with games, however it could potentially record screen shots of other applications and expose sensitive data.  Disabling the feature will prevent this from occurring.


Check Content:
This is NA for Windows 10 LTSC\B versions 1507 and 1607.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\GameDVR\

Value Name: AllowGameDVR

Type: REG_DWORD
Value: 0x00000000 (0)
#>

# No check for LTSB/LTSC
$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\"
    Name = "AllowGameDVR"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params