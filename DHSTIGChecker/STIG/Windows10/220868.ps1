# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220868
Rule ID:    SV-220868r877395_rule
STIG ID:    WN10-CC-000360
Legacy:     V-63341; SV-77831
Rule Title: The Windows Remote Management (WinRM) client must not use Digest authentication.
Discussion:
Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\

Value Name: AllowDigest

Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
    Name          = "AllowDigest"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params