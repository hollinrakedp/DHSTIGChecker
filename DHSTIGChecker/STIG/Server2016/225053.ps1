<#
Rule Title: Windows Server 2016 must be configured to prevent the storage of the LAN Manager hash of passwords.
Severity: high
Vuln ID: V-225053
STIG ID: WN16-SO-000360

Discussion:
The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords. This setting controls whether a LAN Manager hash of the password is stored in the SAM the next time the password is changed.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: NoLMHash

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
