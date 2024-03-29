# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220856
Rule ID:    SV-220856r851997_rule
STIG ID:    WN10-CC-000310
Legacy:     V-63321; SV-77811
Rule Title: Users must be prevented from changing installation options.
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