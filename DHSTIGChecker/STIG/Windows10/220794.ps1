<#
Rule Title: The display of slide shows on the lock screen must be disabled.
Severity: medium
Vuln ID: V-220794
STIG ID: WN10-CC-000010

Discussion:
Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
    Name = "NoLockScreenSlideshow"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params