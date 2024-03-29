# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253404
Rule ID:    SV-253404r829296_rule
STIG ID:    WN11-CC-000280
Legacy:     
Rule Title: Remote Desktop Services must always prompt a client for passwords upon connection.
Discussion:
This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.


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