# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253387
Rule ID:    SV-253387r829245_rule
STIG ID:    WN11-CC-000185
Legacy:     
Rule Title: The default autorun behavior must be configured to prevent autorun commands.
Discussion:
Allowing autorun commands to execute may introduce malicious code to a system. Configuring this setting prevents autorun commands from executing.


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