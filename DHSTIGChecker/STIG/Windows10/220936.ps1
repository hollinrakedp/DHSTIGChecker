# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220936
Rule ID:    SV-220936r569187_rule
STIG ID:    WN10-SO-000190
Legacy:     V-63795; SV-78285
Rule Title: Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
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