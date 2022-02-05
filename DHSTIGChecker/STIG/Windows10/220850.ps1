<#
Rule Title: Remote Desktop Services must always prompt a client for passwords upon connection.
Severity: medium
Vuln ID: V-220850
STIG ID: WN10-CC-000280

Discussion:
This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection.  Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fPromptForPassword

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "fPromptForPassword"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params