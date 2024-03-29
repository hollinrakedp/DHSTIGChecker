# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220794
Rule ID:    SV-220794r569187_rule
STIG ID:    WN10-CC-000010
Legacy:     V-63549; SV-78039
Rule Title: The display of slide shows on the lock screen must be disabled.
Discussion:
Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
    Name = "NoLockScreenSlideshow"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params