<#
Rule Title: Windows 10 must be configured to enable Remote host allows delegation of non-exportable credentials.
Severity: medium
Vuln ID: V-220810
STIG ID: WN10-CC-000068

Discussion:
An exportable version of credentials is provided to remote hosts when using credential delegation which exposes them to theft on the remote host.  Restricted Admin mode or Remote Credential Guard allow delegation of non-exportable credentials providing additional protection of the credentials.  Enabling this configures the host to support Restricted Admin mode or Remote Credential Guard.


Check Content:
This is NA for Windows 10 LTSC\B versions 1507 and 1607.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\

Value Name: AllowProtectedCreds

Type: REG_DWORD
Value: 0x00000001 (1)

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"
    Name = "AllowProtectedCreds"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params