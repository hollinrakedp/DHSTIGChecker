# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-205805
Rule ID:    SV-205805r852507_rule
STIG ID:    WN19-CC-000220
Legacy:     V-93375; SV-103461
Rule Title: Windows Server 2019 default AutoRun behavior must be configured to prevent AutoRun commands.
Discussion:
Allowing AutoRun commands to execute may introduce malicious code to a system. Configuring this setting prevents AutoRun commands from executing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

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