# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-220825
Rule ID:    SV-220825r569187_rule
STIG ID:    WN10-CC-000170
Legacy:     V-63659; SV-78149
Rule Title: The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.
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

# Does not check LTSB
$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name = "MSAOptional"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params