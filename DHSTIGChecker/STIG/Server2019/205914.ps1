# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-205914
Rule ID:    SV-205914r569188_rule
STIG ID:    WN19-SO-000220
Legacy:     V-93291; SV-103379
Rule Title: Windows Server 2019 must not allow anonymous enumeration of Security Account Manager (SAM) accounts.
Discussion:
Anonymous enumeration of SAM accounts allows anonymous logon users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "RestrictAnonymousSAM"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params