<#
Rule Title: The Security event log size must be configured to 1024000 KB or greater.
Severity: medium
Vuln ID: V-220780
STIG ID: WN10-AU-000505

Discussion:
Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.


Check Content:
If the system is configured to send audit records directly to an audit server, this is NA. This must be documented with the ISSO.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\

Value Name: MaxSize

Value Type: REG_DWORD
Value: 0x000fa000 (1024000) (or greater)

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
    Name = "MaxSize"
    ExpectedValue = 1024000
    Comparison = "ge"
}

Compare-RegKeyValue @Params