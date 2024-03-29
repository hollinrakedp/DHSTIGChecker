# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253424
Rule ID:    SV-253424r829356_rule
STIG ID:    WN11-CC-000385
Legacy:     
Rule Title: Windows Ink Workspace must be configured to disallow access above the lock.
Discussion:
This action secures Windows Ink, which contains applications and features oriented toward pen computing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

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