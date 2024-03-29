# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220847
Rule ID:    SV-220847r569187_rule
STIG ID:    WN10-CC-000260
Legacy:     V-63721; SV-78211
Rule Title: Windows 10 must be configured to require a minimum pin length of six characters or greater.
Discussion:
Windows allows the use of PINs as well as biometrics for authentication without sending a password to a network or website where it could be compromised.  Longer minimum PIN lengths increase the available combinations an attacker would have to attempt.  Shorter minimum length significantly reduces the strength.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\

Value Name:  MinimumPINLength

Type:  REG_DWORD
Value:  6 (or greater)
#>

$Params = @{
    Path          = "HKLM:"
    Name          = "MinimumPINLength"
    ExpectedValue = 6
    Comparison = "ge"
}

Compare-RegKeyValue @Params