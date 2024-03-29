# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253409
Rule ID:    SV-253409r829311_rule
STIG ID:    WN11-CC-000305
Legacy:     
Rule Title: Indexing of encrypted files must be turned off.
Discussion:
Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Windows Search\

Value Name: AllowIndexingEncryptedStoresOrItems

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"
    Name          = "AllowIndexingEncryptedStoresOrItems"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params