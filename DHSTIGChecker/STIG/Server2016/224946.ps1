# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224946
Rule ID:    SV-224946r852333_rule
STIG ID:    WN16-CC-000390
Legacy:     V-73571; SV-88235
Rule Title: Remote Desktop Services must always prompt a client for passwords upon connection.
Discussion:
This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.

Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fPromptForPassword

Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "fPromptForPassword"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params