<#
Rule Title: Windows Server 2019 File Explorer shell protocol must run in protected mode.
Severity: medium
Vuln ID: V-205872
STIG ID: WN19-CC-000330

Discussion:
The shell protocol will limit the set of folders that applications can open when run in protected mode. Restricting files an application can open to a limited set of folders increases the security of Windows.


Check Content:
The default behavior is for shell protected mode to be turned on for File Explorer.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: PreXPSP2ShellProtocolBehavior

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
    Name          = "PreXPSP2ShellProtocolBehavior"
    ExpectedValue = 0
}

if (!(Test-RegKeyValueExists -Path $Params.Path -Name $Params.Name)) {
    return $true
}

Compare-RegKeyValue @Params