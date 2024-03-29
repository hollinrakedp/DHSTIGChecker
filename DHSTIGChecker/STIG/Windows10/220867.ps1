# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220867
Rule ID:    SV-220867r852001_rule
STIG ID:    WN10-CC-000355
Legacy:     V-63375; SV-77865
Rule Title: The Windows Remote Management (WinRM) service must not store RunAs credentials.
Discussion:
Storage of administrative credentials could allow unauthorized access.  Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

Value Name: DisableRunAs

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
    Name          = "DisableRunAs"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params