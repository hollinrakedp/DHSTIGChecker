# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224996
Rule ID:    SV-224996r569186_rule
STIG ID:    WN16-DC-000330
Legacy:     V-73631; SV-88295
Rule Title: Domain controllers must be configured to allow reset of machine account passwords.
Discussion:
Enabling this setting on all domain controllers in a domain prevents domain members from changing their computer account passwords. If these passwords are weak or compromised, the inability to change them may leave these computers vulnerable.


Check Content:
This applies to domain controllers. It is NA for other systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RefusePasswordChange

Value Type: REG_DWORD
Value: 0x00000000 (0)
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}