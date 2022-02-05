<#
Rule Title: Windows Ink Workspace must be configured to disallow access above the lock.  
Severity: medium
Vuln ID: V-220871
STIG ID: WN10-CC-000385

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