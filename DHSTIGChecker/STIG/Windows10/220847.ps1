<#
Rule Title: Windows 10 must be configured to require a minimum pin length of six characters or greater.
Severity: medium
Vuln ID: V-220847
STIG ID: WN10-CC-000260

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