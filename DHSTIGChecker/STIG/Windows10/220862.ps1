<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   high
Vuln ID:    V-220862
Rule ID:    SV-220862r569187_rule
STIG ID:    WN10-CC-000330
Legacy:     V-63335; SV-77825
Rule Title: The Windows Remote Management (WinRM) client must not use Basic authentication.
Discussion:
Basic authentication uses plain text passwords that could be used to compromise a system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\

Value Name: AllowBasic

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
    Name          = "AllowBasic"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params