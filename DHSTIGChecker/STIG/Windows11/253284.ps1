# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253284
Rule ID:    SV-253284r828936_rule
STIG ID:    WN11-00-000150
Legacy:     
Rule Title: Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.
Discussion:
Attackers are constantly looking for vulnerabilities in systems and applications. Structured Exception Handling Overwrite Protection (SEHOP) blocks exploits that use the Structured Exception Handling overwrite technique, a common buffer overflow attack.


Check Content:
Verify SEHOP is turned on.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Session Manager\kernel\

Value Name: DisableExceptionChainValidation

Value Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\"
    Name          = "DisableExceptionChainValidation"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params