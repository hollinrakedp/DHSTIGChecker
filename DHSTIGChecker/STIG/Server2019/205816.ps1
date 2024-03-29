# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205816
Rule ID:    SV-205816r877382_rule
STIG ID:    WN19-CC-000480
Legacy:     V-93499; SV-103585
Rule Title: Windows Server 2019 Windows Remote Management (WinRM) client must not allow unencrypted traffic.
Discussion:
Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.

Satisfies: SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\

Value Name: AllowUnencryptedTraffic

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
    Name          = "AllowUnencryptedTraffic"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params