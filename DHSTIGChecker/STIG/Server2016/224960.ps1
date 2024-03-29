# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224960
Rule ID:    SV-224960r877395_rule
STIG ID:    WN16-CC-000520
Legacy:     V-73597; SV-88261
Rule Title: The Windows Remote Management (WinRM) client must not use Digest authentication.
Discussion:
Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks. Disallowing Digest authentication will reduce this potential.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\

Value Name: AllowDigest

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
    Name          = "AllowDigest"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params