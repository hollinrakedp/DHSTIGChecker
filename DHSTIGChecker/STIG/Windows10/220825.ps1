<#
Rule Title: The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.
Severity: low
Vuln ID: V-220825
STIG ID: WN10-CC-000170

Discussion:
Control of credentials and the system must be maintained within the enterprise.  Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.


Check Content:
Windows 10 LTSC\B versions do not support the Microsoft Store and modern apps; this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: MSAOptional

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>

#Does not check LTSB

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name = "MSAOptional"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params