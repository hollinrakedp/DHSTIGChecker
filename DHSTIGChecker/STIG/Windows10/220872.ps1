<#
Rule Title: Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications. 
Severity: low
Vuln ID: V-220872
STIG ID: WN10-CC-000390

Discussion:
Windows spotlight features may suggest apps and content from third-party software publishers in addition to Microsoft apps and content. 


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CloudContent\

Value Name: DisableThirdPartySuggestions

Type: REG_DWORD
Value: 0x00000001 (1)



#>

#Incomplete
return "Not Reviewed"