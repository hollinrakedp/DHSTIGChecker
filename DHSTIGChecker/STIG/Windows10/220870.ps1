<#
Rule Title: The convenience PIN for Windows 10 must be disabled.  
Severity: medium
Vuln ID: V-220870
STIG ID: WN10-CC-000370

Discussion:
This policy controls whether a domain user can sign in using a convenience PIN to prevent enabling (Password Stuffer).


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

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