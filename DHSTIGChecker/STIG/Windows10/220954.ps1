<#
Rule Title: Toast notifications to the lock screen must be turned off.
Severity: low
Vuln ID: V-220954
STIG ID: WN10-UC-000015

Discussion:
Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\

Value Name: NoToastApplicationNotificationOnLockScreen

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\"
    Name          = "NoToastApplicationNotificationOnLockScreen"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params