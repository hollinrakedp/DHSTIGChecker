# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224824
Rule ID:    SV-224824r857226_rule
STIG ID:    WN16-00-000070
Legacy:     V-73231; SV-87883
Rule Title: Manually managed application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.
Discussion:
Setting application account passwords to expire may cause applications to stop functioning. However, not changing them on a regular basis exposes them to attack. If managed service accounts are used, this alleviates the need to manually change application account passwords.


Check Content:
Determine if manually managed application/service accounts exist. If none exist, this is NA.

If passwords for manually managed application/service accounts are not changed at least annually or when an administrator with knowledge of the password leaves the organization, this is a finding.

Identify manually managed application/service accounts.

To determine the date a password was last changed:

Domain controllers:

Open "PowerShell".

Enter "Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet", where [application account name] is the name of the manually managed application/service account.

If the "PasswordLastSet" date is more than one year old, this is a finding.

Member servers and standalone or nondomain-joined systems:

Open "Command Prompt".

Enter 'Net User [application account name] | Find /i "Password Last Set"', where [application account name] is the name of the manually managed application/service account.

If the "Password Last Set" date is more than one year old, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
