# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220866
Rule ID:    SV-220866r877382_rule
STIG ID:    WN10-CC-000350
Legacy:     V-63369; SV-77859
Rule Title: The Windows Remote Management (WinRM) service must not allow unencrypted traffic.
Discussion:
Unencrypted remote access to a system can allow sensitive information to be compromised.  Windows remote management connections must be encrypted to prevent this.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

Value Name: AllowUnencryptedTraffic

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
    Name          = "AllowUnencryptedTraffic"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params