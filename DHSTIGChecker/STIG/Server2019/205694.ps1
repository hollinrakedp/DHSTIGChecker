# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205694
Rule ID:    SV-205694r569188_rule
STIG ID:    WN19-CC-000410
Legacy:     V-93415; SV-103501
Rule Title: Windows Server 2019 must prevent Indexing of encrypted files.
Discussion:
Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Windows Search\

Value Name: AllowIndexingEncryptedStoresOrItems

Value Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"
    Name          = "AllowIndexingEncryptedStoresOrItems"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params