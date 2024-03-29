# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220727
Rule ID:    SV-220727r851967_rule
STIG ID:    WN10-00-000150
Legacy:     V-68849; SV-83445
Rule Title: Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.
Discussion:
Attackers are constantly looking for vulnerabilities in systems and applications. Structured Exception Handling Overwrite Protection (SEHOP) blocks exploits that use the Structured Exception Handling overwrite technique, a common buffer overflow attack.


Check Content:
This is applicable to Windows 10 prior to v1709.

Verify SEHOP is turned on.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Session Manager\kernel\

Value Name: DisableExceptionChainValidation

Value Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Local:AppliesTo = '1507', '1511', '1607', '1703', '1709'

if (!($Local:AppliesTo -contains $Script:ComputerInfo.WindowsVersion)) {
    Write-Verbose "Reason: Version is not < 1709"
    return 'Not Applicable'
}
else {
    $Params = @{
        Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\"
        Name          = "DisableExceptionChainValidation"
        ExpectedValue = 0
    }

    Compare-RegKeyValue @Params
}