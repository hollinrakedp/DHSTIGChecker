# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225042
Rule ID:    SV-225042r852385_rule
STIG ID:    WN16-SO-000230
Legacy:     V-73661; SV-88325
Rule Title: The setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.
Discussion:
The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing.

Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: RequireSecuritySignature

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
    Name          = "RequireSecuritySignature"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params