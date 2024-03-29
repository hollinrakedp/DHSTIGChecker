# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253358
Rule ID:    SV-253358r829158_rule
STIG ID:    WN11-CC-000038
Legacy:     
Rule Title: WDigest Authentication must be disabled.
Discussion:
When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority Subsystem Service (LSASS) exposing them to theft. WDigest is disabled by default in Windows 11. This setting ensures this is enforced.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\

Value Name: UseLogonCredential

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
    Name = "UseLogonCredential"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params