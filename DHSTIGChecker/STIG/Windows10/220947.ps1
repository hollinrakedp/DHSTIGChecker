# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220947
Rule ID:    SV-220947r852017_rule
STIG ID:    WN10-SO-000255
Legacy:     V-63821; SV-78311
Rule Title: User Account Control must automatically deny elevation requests for standard users.
Discussion:
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  Denying elevation requests from standard user accounts requires tasks that need elevation to be initiated by accounts with administrative privileges.  This ensures correct accounts are used on the system for privileged tasks to help mitigate credential theft.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: ConsentPromptBehaviorUser

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name          = "ConsentPromptBehaviorUser"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params