<#
Rule Title: The Windows Remote Management (WinRM) client must not use Digest authentication.
Severity: medium
Vuln ID: V-220868
STIG ID: WN10-CC-000360

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