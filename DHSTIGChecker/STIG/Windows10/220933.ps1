<#
Rule Title: Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.
Severity: medium
Vuln ID: V-220933
STIG ID: WN10-SO-000167

Discussion:
The Windows Security Account Manager (SAM) stores users' passwords.  Restricting remote rpc connections to the SAM to Administrators helps protect those credentials.


Check Content:
Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)

#>

#Incomplete
return "Not Reviewed"