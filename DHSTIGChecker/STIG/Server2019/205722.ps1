<#
Rule Title: Windows Server 2019 Remote Desktop Services must prevent drive redirection.
Severity: medium
Vuln ID: V-205722
STIG ID: WN19-CC-000350

Discussion:
Preventing users from sharing the local drives on their client computers with Remote Session Hosts that they access helps reduce possible exposure of sensitive data.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fDisableCdm

Type: REG_DWORD
Value: 0x00000001 (1)

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "fDisableCdm"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params