# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253384
Rule ID:    SV-253384r829236_rule
STIG ID:    WN11-CC-000170
Legacy:     
Rule Title: The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.
Discussion:
Control of credentials and the system must be maintained within the enterprise. Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: MSAOptional

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name = "MSAOptional"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params