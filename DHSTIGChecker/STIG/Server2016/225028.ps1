# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225028
Rule ID:    SV-225028r569186_rule
STIG ID:    WN16-SO-000050
Legacy:     V-73627; SV-88291
Rule Title: Audit policy using subcategories must be enabled.
Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. 
This setting allows administrators to enable more precise auditing capabilities.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: SCENoApplyLegacyAuditPolicy

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "SCENoApplyLegacyAuditPolicy"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params