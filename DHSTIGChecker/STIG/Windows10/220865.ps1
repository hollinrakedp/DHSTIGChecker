<#
Rule Title: The Windows Remote Management (WinRM) service must not use Basic authentication.
Severity: high
Vuln ID: V-220865
STIG ID: WN10-CC-000345

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