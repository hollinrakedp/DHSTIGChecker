# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225032
Rule ID:    SV-225032r877039_rule
STIG ID:    WN16-SO-000110
Legacy:     V-73639; SV-88303
Rule Title: The computer account password must not be prevented from being reset.
Discussion:
Computer account passwords are changed automatically on a regular basis. Disabling automatic password changes can make the system more vulnerable to malicious access. Frequent password changes can be a significant safeguard for the system. A new password for the computer account will be generated every 30 days.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: DisablePasswordChange

Value Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    Name          = "DisablePasswordChange"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params