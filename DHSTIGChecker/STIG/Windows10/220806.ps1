# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220806
Rule ID:    SV-220806r890427_rule
STIG ID:    WN10-CC-000055
Legacy:     V-63581; SV-78071
Rule Title: Simultaneous connections to the internet or a Windows domain must be limited.
Discussion:
Multiple network connections can provide additional attack vectors to a system and must be limited. The "Minimize the number of simultaneous connections to the Internet or a Windows Domain" setting prevents systems from automatically establishing multiple connections. When both wired and wireless connections are available, for example, the less-preferred connection (typically wireless) will be disconnected.


Check Content:
The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain" is "Enabled".

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "3", this is not a finding.

If it exists and is configured with a value of "0", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\

Value Name: fMinimizeConnections

Value Type: REG_DWORD
Value: 3 (or if the Value Name does not exist)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\"
    Name = "fMinimizeConnections"
    ExpectedValue = 1
}

if (!(Test-RegKeyValueExists -Path $Params.Path -Name $Params.Name)) {
    return $true
}

Compare-RegKeyValue @Params