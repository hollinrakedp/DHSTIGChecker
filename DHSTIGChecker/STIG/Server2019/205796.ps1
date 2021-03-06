<#
Rule Title: Windows Server 2019 Application event log size must be configured to 32768 KB or greater.
Severity: medium
Vuln ID: V-205796
STIG ID: WN19-CC-000270

Discussion:
Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.


Check Content:
If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"
    Name = "MaxSize"
    ExpectedValue = 32768
    Comparison = "ge"
}

Compare-RegKeyValue @Params