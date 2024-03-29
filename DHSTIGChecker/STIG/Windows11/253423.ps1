# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253423
Rule ID:    SV-253423r840184_rule
STIG ID:    WN11-CC-000370
Legacy:     
Rule Title: The convenience PIN for Windows 11 must be disabled.
Discussion:
This policy controls whether a domain user can sign in using a convenience PIN to prevent enabling (Password Stuffer).


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\System

Value Name: AllowDomainPINLogon
Value Type: REG_DWORD
Value data: 0
#>

$Params = @{
    Path          = "HKLM:\Software\Policies\Microsoft\Windows\System"
    Name          = "AllowDomainPINLogon"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params