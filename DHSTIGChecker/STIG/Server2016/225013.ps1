# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225013
Rule ID:    SV-225013r877392_rule
STIG ID:    WN16-MS-000310
Legacy:     V-73677; SV-88341
Rule Title: Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.
Discussion:
The Windows Security Account Manager (SAM) stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials.


Check Content:
This applies to member servers and standalone or nondomain-joined systems. It is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Applicable"
}
else {
    "Not Reviewed"
}