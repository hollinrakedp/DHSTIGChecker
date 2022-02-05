<#
Rule Title: Unencrypted passwords must not be sent to third-party SMB Servers.
Severity: medium
Vuln ID: V-220926
STIG ID: WN10-SO-000110

Discussion:
Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication.  Sending plain text passwords across the network, when authenticating to an SMB server, reduces the overall security of the environment.  Check with the vendor of the SMB server to see if there is a way to support encrypted password authentication.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name:  EnablePlainTextPassword

Value Type:  REG_DWORD
Value:  0

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
    Name          = "EnablePlainTextPassword"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params