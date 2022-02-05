<#
Rule Title: Microsoft consumer experiences must be turned off.
Severity: low
Vuln ID: V-220831
STIG ID: WN10-CC-000197

Discussion:
Microsoft consumer experiences provides suggestions and notifications to users, which may include the installation of Windows Store apps.  Organizations may control the execution of applications through other means such as whitelisting.  Turning off Microsoft consumer experiences will help prevent the unwanted installation of suggested applications.


Check Content:
Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CloudContent\

Value Name: DisableWindowsConsumerFeatures

Type: REG_DWORD
Value: 0x00000001 (1)

#>

#Does not check LTSB

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\"
    Name = "DisableWindowsConsumerFeatures"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params