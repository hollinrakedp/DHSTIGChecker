<#
Rule Title: Local drives must be prevented from sharing with Remote Desktop Session Hosts.
Severity: medium
Vuln ID: V-220849
STIG ID: WN10-CC-000275

Discussion:
Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fDisableCdm

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "fDisableCdm"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params