# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224952
Rule ID:    SV-224952r569186_rule
STIG ID:    WN16-CC-000440
Legacy:     V-73581; SV-88245
Rule Title: Indexing of encrypted files must be turned off.
Discussion:
Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

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