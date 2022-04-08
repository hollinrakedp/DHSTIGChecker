<#
Rule Title: The Windows dialog box title for the legal banner must be configured.
Severity: low
Vuln ID: V-220922
STIG ID: WN10-SO-000080

Discussion:
Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LegalNoticeCaption

Value Type: REG_SZ
Value: See message title above

"DoD Notice and Consent Banner", "US Department of Defense Warning Statement" or a site-defined equivalent, this is a finding.

If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in WN10-SO-000075.

#>

#Incomplete
return "Not Reviewed"