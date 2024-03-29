# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224938
Rule ID:    SV-224938r877391_rule
STIG ID:    WN16-CC-000310
Legacy:     V-73555; SV-88219
Rule Title: The Security event log size must be configured to 196608 KB or greater.
Discussion:
Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.


Check Content:
If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00030000 (196608) (or greater)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
    Name = "MaxSize"
    ExpectedValue = 196608
    Comparison = "ge"
}

Compare-RegKeyValue @Params