# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220839
Rule ID:    SV-220839r569187_rule
STIG ID:    WN10-CC-000225
Legacy:     V-63695; SV-78185
Rule Title: File Explorer shell protocol must run in protected mode.
Discussion:
The shell protocol will  limit the set of folders applications can open when run in protected mode.  Restricting files an application can open, to a limited set of folders, increases the security of Windows.


Check Content:
The default behavior is for shell protected mode to be turned on for file explorer.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: PreXPSP2ShellProtocolBehavior

Value Type: REG_DWORD
Value: 0 (or if the Value Name does not exist)
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