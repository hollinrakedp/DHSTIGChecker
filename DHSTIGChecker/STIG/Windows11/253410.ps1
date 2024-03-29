# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253410
Rule ID:    SV-253410r829314_rule
STIG ID:    WN11-CC-000310
Legacy:     
Rule Title: Users must be prevented from changing installation options.
Discussion:
Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features.


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