<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 2 Benchmark Date: 14 Nov 2022
Severity:   high
Vuln ID:    V-253416
Rule ID:    SV-253416r829332_rule
STIG ID:    WN11-CC-000330
Legacy:     
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