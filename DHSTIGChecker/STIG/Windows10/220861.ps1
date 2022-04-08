<#
Rule Title: The Windows Explorer Preview pane must be disabled for Windows 10. 
Severity: medium
Vuln ID: V-220861
STIG ID: WN10-CC-000328

Discussion:
A known vulnerability in Windows 10 could allow the execution of malicious code by either opening a compromised document or viewing it in the Windows Preview pane.

Organizations must disable the Windows Preview pane and Windows Detail pane.


Check Content:
If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer

Value Name: NoPreviewPane

Value Type: REG_DWORD

Value: 1

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer

Value Name: NoReadingPane

Value Type: REG_DWORD

Value: 1

#>

#Incomplete
return "Not Reviewed"