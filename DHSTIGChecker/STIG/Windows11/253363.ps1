# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253363
Rule ID:    SV-253363r829173_rule
STIG ID:    WN11-CC-000052
Legacy:     
Rule Title: Windows 11 must be configured to prioritize ECC Curves with longer key lengths first.
Discussion:
Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. By default Windows uses ECC curves with shorter key lengths first. Requiring ECC curves with longer key lengths to be prioritized first helps ensure more secure algorithms are used.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\

Value Name: EccCurves

Value Type: REG_MULTI_SZ
Value: NistP384 NistP256
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\"
    Name = "EccCurves"
    ExpectedValue = "NistP384 NistP256"
}

Compare-RegKeyValue @Params