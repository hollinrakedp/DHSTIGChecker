<#
Rule Title: Windows Server 2019 must be configured to require a strong session key.
Severity: medium
Vuln ID: V-205824
STIG ID: WN19-SO-000110

Discussion:
A computer connecting to a domain controller will establish a secure channel. The secure channel connection may be subject to compromise, such as hijacking or eavesdropping, if strong session keys are not used to establish the connection. Requiring strong session keys enforces 128-bit encryption between systems.

Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 0x00000001 (1)
 
This setting may prevent a system from being joined to a domain if not configured consistently between systems.

#>
return 'Not Reviewed'
