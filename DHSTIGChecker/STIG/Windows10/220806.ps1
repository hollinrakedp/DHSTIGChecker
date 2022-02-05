<#
Rule Title: Simultaneous connections to the Internet or a Windows domain must be limited.
Severity: medium
Vuln ID: V-220806
STIG ID: WN10-CC-000055

Discussion:
Multiple network connections can provide additional attack vectors to a system and must be limited. The "Minimize the number of simultaneous connections to the Internet or a Windows Domain" setting prevents systems from automatically establishing multiple connections.  When both wired and wireless connections are available, for example, the less preferred connection (typically wireless) will be disconnected.


Check Content:
The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain" is "Enabled".

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "1", this is not a finding.

If it exists and is configured with a value of "0", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\

Value Name: fMinimizeConnections

Value Type: REG_DWORD
Value: 1 (or if the Value Name does not exist)

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