# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-225046
Rule ID:    SV-225046r569186_rule
STIG ID:    WN16-SO-000270
Legacy:     V-73669; SV-88333
Rule Title: Anonymous enumeration of shares must not be allowed.
Discussion:
Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "RestrictAnonymous"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params