# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205801
Rule ID:    SV-205801r852502_rule
STIG ID:    WN19-CC-000420
Legacy:     V-93199; SV-103287
Rule Title: Windows Server 2019 must prevent users from changing installation options.
Discussion:
Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\

Value Name: EnableUserControl

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
    Name          = "EnableUserControl"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params