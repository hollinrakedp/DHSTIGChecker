# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224963
Rule ID:    SV-224963r852338_rule
STIG ID:    WN16-CC-000550
Legacy:     V-73603; SV-88267
Rule Title: The Windows Remote Management (WinRM) service must not store RunAs credentials.
Discussion:
Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.

Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

Value Name: DisableRunAs

Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
    Name          = "DisableRunAs"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params