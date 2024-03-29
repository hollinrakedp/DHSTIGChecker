# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224915
Rule ID:    SV-224915r569186_rule
STIG ID:    WN16-CC-000030
Legacy:     V-73497; SV-88149
Rule Title: WDigest Authentication must be disabled on Windows Server 2016.
Discussion:
When the WDigest Authentication protocol is enabled, plain-text passwords are stored in the Local Security Authority Subsystem Service (LSASS), exposing them to theft. WDigest is disabled by default in Windows Server 2016. This setting ensures this is enforced.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\

Value Name:  UseLogonCredential

Type:  REG_DWORD
Value:  0x00000000 (0)
#>

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
    Name = "UseLogonCredential"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params