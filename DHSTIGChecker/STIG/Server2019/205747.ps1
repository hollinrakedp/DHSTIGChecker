# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205747
Rule ID:    SV-205747r877392_rule
STIG ID:    WN19-MS-000060
Legacy:     V-93045; SV-103133
Rule Title: Windows Server 2019 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems.
Discussion:
The Windows SAM stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials.


Check Content:
This applies to member servers and standalone or nondomain-joined systems. It is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)
#>

# Partial
if ($Script:IsDomainController) {
    "Not Applicable"
}
else {
    "Not Reviewed"
}