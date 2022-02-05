<#
Rule Title: The system must be configured to require a strong session key.
Severity: medium
Vuln ID: V-220919
STIG ID: WN10-SO-000060

Discussion:
A computer connecting to a domain controller will establish a secure channel.  Requiring strong session keys enforces 128-bit encryption between systems.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 1
 
Warning: This setting may prevent a system from being joined to a domain if not configured consistently between systems.

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    Name          = "RequireStrongKey"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params