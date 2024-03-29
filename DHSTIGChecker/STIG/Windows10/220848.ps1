# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220848
Rule ID:    SV-220848r851994_rule
STIG ID:    WN10-CC-000270
Legacy:     V-63729; SV-78219
Rule Title: Passwords must not be saved in the Remote Desktop Client.
Discussion:
Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system.  The system must be configured to prevent users from saving passwords in the Remote Desktop Client.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: DisablePasswordSaving

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "DisablePasswordSaving"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params