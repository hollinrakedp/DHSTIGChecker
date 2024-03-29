# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-205711
Rule ID:    SV-205711r877395_rule
STIG ID:    WN19-CC-000470
Legacy:     V-93503; SV-103589
Rule Title: Windows Server 2019 Windows Remote Management (WinRM) client must not use Basic authentication.
Discussion:
Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
    Name          = "AllowBasic"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params