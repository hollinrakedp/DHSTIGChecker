<#
Rule Title: The setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled.
Severity: medium
Vuln ID: V-225029
STIG ID: WN16-SO-000080

Discussion:
Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.

Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RequireSignOrSeal

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
