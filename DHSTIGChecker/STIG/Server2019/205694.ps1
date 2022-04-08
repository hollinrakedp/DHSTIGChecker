<#
Rule Title: Windows Server 2019 must prevent Indexing of encrypted files.
Severity: medium
Vuln ID: V-205694
STIG ID: WN19-CC-000410

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
return 'Not Reviewed'
