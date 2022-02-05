<#
Rule Title: The Windows Installer Always install with elevated privileges must be disabled.
Severity: high
Vuln ID: V-220857
STIG ID: WN10-CC-000315

Discussion:
Standard user accounts must not be granted elevated privileges.  Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\

Value Name: AlwaysInstallElevated

Value Type: REG_DWORD
Value: 0

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
    Name          = "AlwaysInstallElevated"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params