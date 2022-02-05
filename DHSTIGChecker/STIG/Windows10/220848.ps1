<#
Rule Title: Passwords must not be saved in the Remote Desktop Client.
Severity: medium
Vuln ID: V-220848
STIG ID: WN10-CC-000270

Discussion:
Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system.  The system must be configured to prevent users from saving passwords in the Remote Desktop Client.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: DisablePasswordSaving

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "DisablePasswordSaving"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params