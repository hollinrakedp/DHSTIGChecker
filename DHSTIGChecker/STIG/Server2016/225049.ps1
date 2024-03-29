# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225049
Rule ID:    SV-225049r569186_rule
STIG ID:    WN16-SO-000320
Legacy:     V-73679; SV-88343
Rule Title: Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.
Discussion:
Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously versus using the computer identity.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\

Value Name: UseMachineId

Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\"
    Name          = "UseMachineId"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params