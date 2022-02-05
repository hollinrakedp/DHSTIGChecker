<#
Rule Title: The default autorun behavior must be configured to prevent autorun commands.
Severity: high
Vuln ID: V-220828
STIG ID: WN10-CC-000185

Discussion:
Allowing autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents autorun commands from executing.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoAutorun

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
    Name = "NoAutorun"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params