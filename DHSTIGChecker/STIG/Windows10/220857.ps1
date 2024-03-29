# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220857
Rule ID:    SV-220857r851998_rule
STIG ID:    WN10-CC-000315
Legacy:     V-63325; SV-77815
Rule Title: The Windows Installer Always install with elevated privileges must be disabled.
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