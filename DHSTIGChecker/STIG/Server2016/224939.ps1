# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224939
Rule ID:    SV-224939r877391_rule
STIG ID:    WN16-CC-000320
Legacy:     V-73557; SV-88221
Rule Title: The System event log size must be configured to 32768 KB or greater.
Discussion:
Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.


Check Content:
If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\EventLog\System\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"
    Name = "MaxSize"
    ExpectedValue = 32768
    Comparison = "ge"
}

Compare-RegKeyValue @Params