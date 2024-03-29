# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-224933
Rule ID:    SV-224933r852326_rule
STIG ID:    WN16-CC-000260
Legacy:     V-73547; SV-88211
Rule Title: The default AutoRun behavior must be configured to prevent AutoRun commands.
Discussion:
Allowing AutoRun commands to execute may introduce malicious code to a system. Configuring this setting prevents AutoRun commands from executing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoAutorun

Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
    Name = "NoAutorun"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params