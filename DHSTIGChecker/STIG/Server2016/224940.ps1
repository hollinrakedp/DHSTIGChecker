<#
Rule Title: Windows Server 2016 Windows SmartScreen must be enabled.
Severity: medium
Vuln ID: V-224940
STIG ID: WN16-CC-000330

Discussion:
Windows SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen will warn users of potentially malicious programs.


Check Content:
This is applicable to unclassified systems; for other systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
