<#
Rule Title: Users must be prevented from changing installation options.
Severity: medium
Vuln ID: V-220856
STIG ID: WN10-CC-000310

Discussion:
Installation options for applications are typically controlled by administrators.  This setting prevents users from changing installation options that may bypass security features.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\

Value Name: EnableUserControl

Value Type: REG_DWORD
Value: 0

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
    Name          = "EnableUserControl"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params