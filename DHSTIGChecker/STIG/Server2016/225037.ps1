<#
Rule Title: The Windows dialog box title for the legal banner must be configured with the appropriate text.
Severity: low
Vuln ID: V-225037
STIG ID: WN16-SO-000160

Discussion:
Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.

Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000228-GPOS-00088


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LegalNoticeCaption

Value Type: REG_SZ
Value: See message title options below

"DoD Notice and Consent Banner", "US Department of Defense Warning Statement", or an organization-defined equivalent. 

If an organization-defined title is used, it can in no case contravene or modify the language of the banner text required in WN16-SO-000150.

Automated tools may only search for the titles defined above. If an organization-defined title is used, a manual review will be required.

#>
return 'Not Reviewed'
