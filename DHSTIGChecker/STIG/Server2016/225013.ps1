<#
Rule Title: Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.
Severity: medium
Vuln ID: V-225013
STIG ID: WN16-MS-000310

Discussion:
The Windows Security Account Manager (SAM) stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials.


Check Content:
This applies to member servers and standalone systems; it is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)

#>
return 'Not Reviewed'
