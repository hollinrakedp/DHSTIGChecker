# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253390
Rule ID:    SV-253390r829254_rule
STIG ID:    WN11-CC-000197
Legacy:     
Rule Title: Microsoft consumer experiences must be turned off.
Discussion:
Microsoft consumer experiences provides suggestions and notifications to users, which may include the installation of Windows Store apps. Organizations may control the execution of applications through other means such as allowlisting. Turning off Microsoft consumer experiences will help prevent the unwanted installation of suggested applications.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CloudContent\

Value Name: DisableWindowsConsumerFeatures

Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\"
    Name = "DisableWindowsConsumerFeatures"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params