<#
Rule Title: Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
Severity: medium
Vuln ID: V-220936
STIG ID: WN10-SO-000190

Discussion:
Certain encryption types are no longer considered secure.  This setting configures a minimum encryption type for Kerberos, preventing the use of the DES and RC4 encryption suites.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\

Value Name: SupportedEncryptionTypes

Value Type: REG_DWORD
Value: 0x7ffffff8 (2147483640)

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
    Name          = "SupportedEncryptionTypes"
    ExpectedValue = 2147483640
}

Compare-RegKeyValue @Params