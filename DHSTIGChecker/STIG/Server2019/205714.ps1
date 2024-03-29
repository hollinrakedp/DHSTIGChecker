# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205714
Rule ID:    SV-205714r569188_rule
STIG ID:    WN19-CC-000240
Legacy:     V-93517; SV-103603
Rule Title: Windows Server 2019 administrator accounts must not be enumerated during elevation.
Discussion:
Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\

Value Name: EnumerateAdministrators

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"
    Name = "EnumerateAdministrators"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params