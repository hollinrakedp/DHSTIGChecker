# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253418
Rule ID:    SV-253418r877395_rule
STIG ID:    WN11-CC-000345
Legacy:     
Rule Title: The Windows Remote Management (WinRM) service must not use Basic authentication.
Discussion:
Basic authentication uses plain text passwords that could be used to compromise a system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

Value Name: AllowBasic

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
    Name          = "AllowBasic"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params