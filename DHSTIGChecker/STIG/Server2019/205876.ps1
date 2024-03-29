# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205876
Rule ID:    SV-205876r569188_rule
STIG ID:    WN19-DC-000330
Legacy:     V-93273; SV-103361
Rule Title: Windows Server 2019 domain controllers must be configured to allow reset of machine account passwords.
Discussion:
Enabling this setting on all domain controllers in a domain prevents domain members from changing their computer account passwords. If these passwords are weak or compromised, the inability to change them may leave these computers vulnerable.


Check Content:
This applies to domain controllers. It is NA for other systems.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RefusePasswordChange

Value Type: REG_DWORD
Value: 0x00000000 (0)
#>

if ($Script:IsDomainController) {
    $Params = @{
        Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
        Name          = "RefusePasswordChange"
        ExpectedValue = 0
    }

    Compare-RegKeyValue @Params
}
else {
    "Not Applicable"
}