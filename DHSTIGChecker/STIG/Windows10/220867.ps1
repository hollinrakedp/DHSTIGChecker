<#
Rule Title: The Windows Remote Management (WinRM) service must not store RunAs credentials.
Severity: medium
Vuln ID: V-220867
STIG ID: WN10-CC-000355

Discussion:
Storage of administrative credentials could allow unauthorized access.  Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

Value Name: DisableRunAs

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
    Name          = "DisableRunAs"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params