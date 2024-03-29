# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220828
Rule ID:    SV-220828r851990_rule
STIG ID:    WN10-CC-000185
Legacy:     V-63671; SV-78161
Rule Title: The default autorun behavior must be configured to prevent autorun commands.
Discussion:
Allowing autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents autorun commands from executing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoAutorun

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
    Name = "NoAutorun"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params