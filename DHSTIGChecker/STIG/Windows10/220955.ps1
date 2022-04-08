<#
Rule Title: Zone information must be preserved when saving attachments.
Severity: medium
Vuln ID: V-220955
STIG ID: WN10-UC-000020

Discussion:
Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.


Check Content:
The default behavior is for Windows to mark file attachments with their zone information.

If the registry Value Name below does not exist, this is not a finding.

If it exists and is configured with a value of "2", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: SaveZoneInformation

Value Type: REG_DWORD
Value: 0x00000002 (2) (or if the Value Name does not exist)

#>

#Incomplete
return "Not Reviewed"