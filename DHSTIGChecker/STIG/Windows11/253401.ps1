# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253401
Rule ID:    SV-253401r829287_rule
STIG ID:    WN11-CC-000260
Legacy:     
Rule Title: Windows 11 must be configured to require a minimum pin length of six characters or greater.
Discussion:
Windows allows the use of PINs as well as biometrics for authentication without sending a password to a network or website where it could be compromised. Longer minimum PIN lengths increase the available combinations an attacker would have to attempt. Shorter minimum length significantly reduces the strength.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\

Value Name: MinimumPINLength

Type: REG_DWORD
Value: 6 (or greater)
#>

$Params = @{
    Path          = "HKLM:"
    Name          = "MinimumPINLength"
    ExpectedValue = 6
    Comparison = "ge"
}

Compare-RegKeyValue @Params