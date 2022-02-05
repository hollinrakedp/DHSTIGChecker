<#
Rule Title: WDigest Authentication must be disabled.
Severity: medium
Vuln ID: V-220800
STIG ID: WN10-CC-000038

Discussion:
When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority Subsystem Service (LSASS) exposing them to theft.  WDigest is disabled by default in Windows 10.  This setting ensures this is enforced.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\

Value Name: UseLogonCredential

Type: REG_DWORD
Value:  0x00000000 (0)

#>

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
    Name = "UseLogonCredential"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params