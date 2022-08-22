<#
Rule Title: Windows Server 2019 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone systems.
Severity: medium
Vuln ID: V-205747
STIG ID: WN19-MS-000060

Discussion:
The Windows SAM stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials.


Check Content:
This applies to member servers and standalone systems; it is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)

#>

if ($Script:IsDomainController) {
    "Not Applicable"
}
else {
    "Not Reviewed"
}