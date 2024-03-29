# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220871
Rule ID:    SV-220871r642141_rule
STIG ID:    WN10-CC-000385
Legacy:     V-99561; SV-108665
Rule Title: Windows Ink Workspace must be configured to disallow access above the lock.  
Discussion:
This action secures Windows Ink, which contains applications and features oriented toward pen computing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsInkWorkspace

Value Name: AllowWindowsInkWorkspace
Value Type: REG_DWORD
Value data: 1
#>

$Params = @{
    Path          = "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace"
    Name          = "AllowWindowsInkWorkspace"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params