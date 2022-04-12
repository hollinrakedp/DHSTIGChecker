<#
Rule Title: User Account Control must virtualize file and registry write failures to per-user locations.
Severity: medium
Vuln ID: V-225068
STIG ID: WN16-SO-000530

Discussion:
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures non-UAC-compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.


Check Content:
UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2016 versus Server with Desktop Experience) as well as Nano Server.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name          = "EnableVirtualization"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params