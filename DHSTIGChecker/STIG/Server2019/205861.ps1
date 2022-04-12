<#
Rule Title: Windows Server 2019 insecure logons to an SMB server must be disabled.
Severity: medium
Vuln ID: V-205861
STIG ID: WN19-CC-000070

Discussion:
Insecure guest logons allow unauthenticated access to shared folders. Shared resources on a system must require authentication to establish proper access.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\

Value Name: AllowInsecureGuestAuth

Type: REG_DWORD
Value: 0x00000000 (0)

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
    Name = "AllowInsecureGuestAuth"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params