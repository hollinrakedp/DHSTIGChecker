# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225052
Rule ID:    SV-225052r569186_rule
STIG ID:    WN16-SO-000350
Legacy:     V-73685; SV-88349
Rule Title: Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
Discussion:
Certain encryption types are no longer considered secure. The DES and RC4 encryption suites must not be used for Kerberos encryption.

Note: Organizations with domain controllers running earlier versions of Windows where RC4 encryption is enabled, selecting "The other domain supports Kerberos AES Encryption" on domain trusts, may be required to allow client communication across the trust relationship.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

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