<#
Rule Title: Automatically signing in the last interactive user after a system-initiated restart must be disabled.
Severity: medium
Vuln ID: V-224956
STIG ID: WN16-CC-000480

Discussion:
Windows can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.


Check Content:
Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: DisableAutomaticRestartSignOn

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
