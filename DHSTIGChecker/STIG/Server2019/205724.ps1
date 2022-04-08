<#
Rule Title: Windows Server 2019 must not allow anonymous enumeration of shares.
Severity: high
Vuln ID: V-205724
STIG ID: WN19-SO-000230

Discussion:
Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
