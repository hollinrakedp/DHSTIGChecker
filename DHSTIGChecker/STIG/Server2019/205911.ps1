<#
Rule Title: Windows Server 2019 maximum age for machine account passwords must be configured to 30 days or less.
Severity: medium
Vuln ID: V-205911
STIG ID: WN19-SO-000100

Discussion:
Computer account passwords are changed automatically on a regular basis. This setting controls the maximum password age that a machine account may have. This must be set to no more than 30 days, ensuring the machine changes its password monthly.


Check Content:
This is the default configuration for this setting (30 days).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: MaximumPasswordAge

Value Type: REG_DWORD
Value: 0x0000001e (30) (or less, but not 0)

#>
return 'Not Reviewed'