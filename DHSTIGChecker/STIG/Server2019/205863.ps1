# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205863
Rule ID:    SV-205863r569188_rule
STIG ID:    WN19-CC-000100
Legacy:     V-93243; SV-103331
Rule Title: Windows Server 2019 must be configured to enable Remote host allows delegation of non-exportable credentials.
Discussion:
An exportable version of credentials is provided to remote hosts when using credential delegation which exposes them to theft on the remote host.  Restricted Admin mode or Remote Credential Guard allow delegation of non-exportable credentials providing additional protection of the credentials.  Enabling this configures the host to support Restricted Admin mode or Remote Credential Guard.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

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