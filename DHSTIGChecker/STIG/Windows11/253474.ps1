# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253474
Rule ID:    SV-253474r829506_rule
STIG ID:    WN11-SO-000270
Legacy:     
Rule Title: User Account Control must run all administrators in Admin Approval Mode, enabling UAC.
Discussion:
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting enables UAC.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: EnableLUA

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name          = "EnableLUA"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params