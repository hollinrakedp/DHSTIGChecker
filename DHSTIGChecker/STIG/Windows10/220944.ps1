# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220944
Rule ID:    SV-220944r852016_rule
STIG ID:    WN10-SO-000245
Legacy:     V-63817; SV-78307
Rule Title: User Account Control approval mode for the built-in Administrator must be enabled.
Discussion:
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: FilterAdministratorToken

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name          = "FilterAdministratorToken"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params