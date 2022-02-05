<#
Rule Title: Camera access from the lock screen must be disabled.
Severity: medium
Vuln ID: V-220792
STIG ID: WN10-CC-000005

Discussion:
Enabling camera access from the lock screen could allow for unauthorized use.  Requiring logon will ensure the device is only used by authorized personnel.


Check Content:
If the device does not have a camera, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\

Value Name: NoLockScreenCamera

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
    Name = "NoLockScreenCamera"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params