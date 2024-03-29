# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220951
Rule ID:    SV-220951r569187_rule
STIG ID:    WN10-SO-000275
Legacy:     V-63831; SV-78321
Rule Title: User Account Control must virtualize file and registry write failures to per-user locations.
Discussion:
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures non-UAC compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name          = "EnableVirtualization"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params