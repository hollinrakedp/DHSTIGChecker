# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205700
Rule ID:    SV-205700r857294_rule
STIG ID:    WN19-00-000200
Legacy:     V-93439; SV-103525
Rule Title: Windows Server 2019 accounts must require passwords.
Discussion:
The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources. Accounts on a system must require passwords.


Check Content:
Review the password required status for enabled user accounts.

Open "PowerShell".

Domain Controllers:

Enter "Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name, Passwordnotrequired, Enabled".

Exclude disabled accounts (e.g., DefaultAccount, Guest) and Trusted Domain Objects (TDOs).

If "Passwordnotrequired" is "True" or blank for any enabled user account, this is a finding.

Member servers and standalone or nondomain-joined systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount'.

Exclude disabled accounts (e.g., DefaultAccount, Guest).

If any enabled user accounts are returned with a "PasswordRequired" status of "False", this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
